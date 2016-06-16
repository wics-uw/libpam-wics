#define PAM_SM_ACCOUNT
#define LDAP_DEPRECATED 1
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>

#ifndef LDAP_SASL_QUIET
#  define LDAP_SASL_QUIET 0
#endif

#ifndef LOG_AUTHPRIV
#  define LOG_AUTHPRIV LOG_AUTH
#endif

#ifndef PAM_EXTERN
#  define PAM_EXTERN extern
#endif

#define PAM_WICS_WICS_BASE_DN         "ou=People,dc=wics,dc=uwaterloo,dc=ca"
#define PAM_WICS_LDAP_TIMEOUT        5
#define PAM_WICS_ALLOWED_USERNAMES   {"nobody"}
#define PAM_WICS_EXPIRED_MSG \
    "*****************************************************************************\n" \
    "*   Your account has expired. Please contact the WiCS Systems Committee.    *\n" \
    "*****************************************************************************\n"

#define PAM_WICS_SYSLOG_EXPIRED_NO_TERMS \
    "(pam_wics): %s was not registered for current term or previous term - denying login\n"
#define PAM_WICS_SYSLOG_EXPIRED_LAST_TERM \
    "(pam_wics): %s was not registered for current term but was registered for previous term - permitting login\n"
#define PAM_WICS_SYSLOG_NOT_A_MEMBER \
    "(pam_wics): %s is not a member account - permitting login\n"
#define PAM_WICS_SYSLOG_SASL_UNRECOGNIZED_CALLBACK \
    "(pam_wics): %ld is not a recognized SASL callback option\n"

/*
 * User terms are defined as (3 * year + term) where term is:
 *   0 = Winter, 1 = Spring, 2 = Fall
 * Term is a string in the form [f|w|s][year]
 */

#define HANDLE_WARN \
{ \
    syslog(LOG_AUTHPRIV | LOG_WARNING, "pam_wics generated a warning on line %d of %s\n", __LINE__, __FILE__); \
    retval = PAM_SUCCESS; \
    goto cleanup; \
}

#define WARN_ZERO(x) \
    if( (x) == 0 ) HANDLE_WARN

#define WARN_NEG1(x) \
    if( (x) == -1 ) HANDLE_WARN

#define WARN_PAM(x) \
    if( (x) != PAM_SUCCESS ) HANDLE_WARN

#define WARN_LDAP(x) \
    if( (x) != LDAP_SUCCESS ) HANDLE_WARN

struct pam_wics_sasl_interact_param
{
    const char* realm;
    const char* user;
    char pass[100];
};
typedef struct pam_wics_sasl_interact_param pam_wics_sasl_interact_param_t;

int pam_wics_sasl_interact(LDAP* ld, unsigned flags, void* def, void* inter)
{
    pam_wics_sasl_interact_param_t* param = (pam_wics_sasl_interact_param_t*)def;
    sasl_interact_t* interact = (sasl_interact_t*)interact;
    while(interact->id != SASL_CB_LIST_END)
    {
        switch(interact->id)
        {
        case SASL_CB_GETREALM:
            interact->result = param->realm;
            break;
        case SASL_CB_USER:
            interact->result = param->user;
            break;
        case SASL_CB_PASS:
            interact->result = param->pass;
            break;
        default:
            syslog(LOG_AUTHPRIV | LOG_NOTICE,
                PAM_WICS_SYSLOG_SASL_UNRECOGNIZED_CALLBACK, interact->id);
            interact->result = "";
            break;
        }
        interact->len = strlen(interact->result);
    }

    return LDAP_SUCCESS;
}

char* pam_wics_escape_ldap_string(const char* src)
{
    char *dst, *dst_ptr;
    int i;

    if(!(dst = malloc(2 * strlen(src) + 1)))
        return NULL;
    dst_ptr = dst;

    for(i = 0; i < strlen(src); i++)
    {
        if(src[i] == '*' || src[i] == '(' || src[i] == ')' || src[i] == '\\')
        {
            dst_ptr[0] = '\\';
            dst_ptr++;
        }
        dst_ptr[0] = src[i];
        dst_ptr++;
    }
    dst_ptr[0] = '\0';

    return dst;
}

int pam_wics_print_message(pam_handle_t* pamh, char* msg, int style)
{
    int retval = PAM_SUCCESS;
    const struct pam_conv* conv;
    struct pam_message message;
    struct pam_message* messages[1];
    struct pam_response* response;

    /* output message */
    WARN_PAM( pam_get_item(pamh, PAM_CONV, (const void**)&conv) )
    if(!conv || !conv->conv)
        goto cleanup;
    messages[0] = &message;
    message.msg_style = style;
    message.msg = msg;
    WARN_PAM( conv->conv(1, (const struct pam_message**)messages,
        &response, conv->appdata_ptr) )

cleanup:

    return retval;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char* argv[])
{
    int retval = PAM_SUCCESS;
    const char* username;
    struct passwd* pwd;
    struct group *grp;
    const char* allowed_usernames[] = PAM_WICS_ALLOWED_USERNAMES;
    unsigned int i;
    time_t cur_time;
    struct tm* local_time;
    int long_term, term_month;
    static const char term_chars[] = {'w', 's', 'f'};
    char cur_term[6], prev_term[6];
    LDAP *ld_wics = NULL;
    char* username_escaped = NULL;
    char *filter_wics = NULL;
    char *attrs_wics[] = {"objectClass", "term", NULL};
    bool expired, syscom = 0; 
    const char* pam_rhost;
    int msg_wics;
    LDAPMessage *res_wics = NULL;
    struct timeval timeout = {PAM_WICS_LDAP_TIMEOUT, 0};
    LDAPMessage* entry = NULL;
    char **values = NULL, **values_iter = NULL;

    /* determine username */
    if((pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) || !username)
    {
        return PAM_USER_UNKNOWN;
    }

    /* check uid range */
    pwd = getpwnam(username);
    if(pwd)
    {
        /* these ranges are taken from puppet/documents/id-range */
        if(pwd->pw_uid < 500 || (pwd->pw_uid >= 1000 && pwd->pw_uid < 10000))
        {
            return PAM_SUCCESS;
        }
    }

    /* check to see if user is in group syscom, if yes, still print message but allow login even if user expired */
    grp = getgrnam("syscom");
    for(i = 0; grp && grp->gr_mem[i]; i++) {
        if(!strcmp(grp->gr_mem[i], username)) {
            syscom = 1;
            break;
        }
    }

    /* check username */
    for(i = 0; i < sizeof(allowed_usernames) / sizeof(char*); i++)
    {
        if(strcmp(allowed_usernames[i], username) == 0)
        {
            return PAM_SUCCESS;
        }
    }

    /* escape username */
    WARN_ZERO( username_escaped = pam_wics_escape_ldap_string(username) );

    /* get term info and compute current and previous term */
    WARN_NEG1( cur_time = time(NULL) )
    WARN_ZERO( local_time = localtime(&cur_time) )
    long_term = 3 * (1900 + local_time->tm_year) + (local_time->tm_mon / 4);
    sprintf(cur_term, "%c%d", term_chars[long_term % 3], long_term / 3);
    long_term--;
    sprintf(prev_term, "%c%d", term_chars[long_term % 3], long_term / 3);
    term_month = local_time->tm_mon % 4;

    /* connect to WICS */
    WARN_LDAP( ldap_create(&ld_wics) )
    WARN_NEG1( ldap_simple_bind(ld_wics, NULL, NULL) )

    /* create WICS request string */
    WARN_ZERO( filter_wics = malloc(140 + strlen(username_escaped)) )
    sprintf(filter_wics, "(&(uid=%s)(|(&(objectClass=member)(|(term=%s)(term=%s)))(!(objectClass=member))))", username_escaped, cur_term, prev_term);

    /* issue WICS request */
    WARN_NEG1( msg_wics = ldap_search(ld_wics, PAM_WICS_WICS_BASE_DN,
        LDAP_SCOPE_SUBTREE, filter_wics, attrs_wics, 0) )

    /* wait for WICS response */
    WARN_NEG1( ldap_result(ld_wics, msg_wics, 1, &timeout, &res_wics) )

    /* check if we received an entry from WICS */
    if(ldap_count_entries(ld_wics, res_wics) == 0)
    {
        /* show notice and disallow login */
        pam_wics_print_message(pamh, PAM_WICS_EXPIRED_MSG, PAM_ERROR_MSG);
        syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_WICS_SYSLOG_EXPIRED_NO_TERMS,
            username);
        retval = (syscom ? PAM_SUCCESS : PAM_AUTH_ERR);
        goto cleanup;
    }

    /* get WICS entry */
    WARN_ZERO( entry = ldap_first_entry(ld_wics, res_wics) )
    values = ldap_get_values(ld_wics, entry, "term");

    if(!values)
    {
        syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_WICS_SYSLOG_NOT_A_MEMBER,
            username);
        retval = PAM_SUCCESS;
        goto cleanup;
    }

    /* iterate through term attributes */
    expired = true;
    if (values) {
        values_iter = values;
        while(*values_iter)
        {
            if(strcmp(*values_iter, cur_term) == 0)
            {
                /* user is registered in current term */
                expired = false;
                break;
            }
            values_iter++;
        }
    }

    /* check if account is expired */
    if(expired)
    {
        /* we allow once month grace-period */
        if(term_month == 0)
        {
            /* show notice and continue */
            pam_wics_print_message(pamh, PAM_WICS_EXPIRED_MSG, PAM_TEXT_INFO);
            syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_WICS_SYSLOG_EXPIRED_LAST_TERM,
                username);
        }
        else
        {
            /* show notice and disallow login */
            pam_wics_print_message(pamh, PAM_WICS_EXPIRED_MSG, PAM_ERROR_MSG);
            syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_WICS_SYSLOG_EXPIRED_NO_TERMS,
                username);
            retval = (syscom ? PAM_SUCCESS : PAM_AUTH_ERR);
        }
    }

cleanup:
    if(values) ldap_value_free(values);
    if(res_wics) ldap_msgfree(res_wics);
    if(ld_wics) ldap_unbind(ld_wics);
    if(filter_wics) free(filter_wics);
    if(username_escaped) free(username_escaped);
    return retval;
}

