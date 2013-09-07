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

#define PAM_CSC_CSC_BASE_DN         "ou=People,dc=csclub,dc=uwaterloo,dc=ca"
#define PAM_CSC_LDAP_TIMEOUT        5
#define PAM_CSC_ALLOWED_USERNAMES   {"nobody"}
#define PAM_CSC_EXPIRED_MSG \
    "*****************************************************************************\n" \
    "*                                                                           *\n" \
    "*    Your account has expired - please contact the Computer Science Club    *\n" \
    "*                                                                           *\n" \
    "*****************************************************************************\n"

#define PAM_CSC_SYSLOG_EXPIRED_NO_TERMS \
    "(pam_csc): %s was not registered for current term or previous term - denying login\n"
#define PAM_CSC_SYSLOG_EXPIRED_LAST_TERM \
    "(pam_csc): %s was not registered for current term but was registered for previous term - permitting login\n"
#define PAM_CSC_SYSLOG_NOT_A_MEMBER \
    "(pam_csc): %s is not a member account - permitting login\n"
#define PAM_CSC_SYSLOG_SASL_UNRECOGNIZED_CALLBACK \
    "(pam_csc): %ld is not a recognized SASL callback option\n"

/*
 * User terms are defined as (3 * year + term) where term is:
 *   0 = Winter, 1 = Spring, 2 = Fall
 * Term is a string in the form [f|w|s][year]
 */

#define HANDLE_WARN \
{ \
    syslog(LOG_AUTHPRIV | LOG_WARNING, "pam_csc generated a warning on line %d of %s\n", __LINE__, __FILE__); \
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

struct pam_csc_sasl_interact_param
{
    const char* realm;
    const char* user;
    char pass[100];
};
typedef struct pam_csc_sasl_interact_param pam_csc_sasl_interact_param_t;

int pam_csc_sasl_interact(LDAP* ld, unsigned flags, void* def, void* inter)
{
    pam_csc_sasl_interact_param_t* param = (pam_csc_sasl_interact_param_t*)def;
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
                PAM_CSC_SYSLOG_SASL_UNRECOGNIZED_CALLBACK, interact->id);
            interact->result = "";
            break;
        }
        interact->len = strlen(interact->result);
    }

    return LDAP_SUCCESS;
}

char* pam_csc_escape_ldap_string(const char* src)
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

int pam_csc_print_message(pam_handle_t* pamh, char* msg, int style)
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
    const char* allowed_usernames[] = PAM_CSC_ALLOWED_USERNAMES;
    unsigned int i;
    time_t cur_time;
    struct tm* local_time;
    int long_term, term_month;
    static const char term_chars[] = {'w', 's', 'f'};
    char cur_term[6], prev_term[6];
    LDAP *ld_csc = NULL;
    char* username_escaped = NULL;
    char *filter_csc = NULL;
    char *attrs_csc[] = {"objectClass", "term", "nonMemberTerm", NULL};
    bool expired, syscom = 0; 
    const char* pam_rhost;
    int msg_csc;
    LDAPMessage *res_csc = NULL;
    struct timeval timeout = {PAM_CSC_LDAP_TIMEOUT, 0};
    LDAPMessage* entry = NULL;
    char **values = NULL, **nmvalues = NULL, **values_iter = NULL;

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
    WARN_ZERO( username_escaped = pam_csc_escape_ldap_string(username) );

    /* get term info and compute current and previous term */
    WARN_NEG1( cur_time = time(NULL) )
    WARN_ZERO( local_time = localtime(&cur_time) )
    long_term = 3 * (1900 + local_time->tm_year) + (local_time->tm_mon / 4);
    sprintf(cur_term, "%c%d", term_chars[long_term % 3], long_term / 3);
    long_term--;
    sprintf(prev_term, "%c%d", term_chars[long_term % 3], long_term / 3);
    term_month = local_time->tm_mon % 4;

    /* connect to CSC */
    WARN_LDAP( ldap_create(&ld_csc) )
    WARN_NEG1( ldap_simple_bind(ld_csc, NULL, NULL) )

    /* check if we are logging in from a CSCF teaching thin client */
    if(pam_get_item(pamh, PAM_RHOST, (const void**)&pam_rhost) && pam_rhost)
    {
        /* TODO: check if pam_rhost is tcNNN.student.cs */
    }

    /* create CSC request string */
    WARN_ZERO( filter_csc = malloc(140 + strlen(username_escaped)) )
    sprintf(filter_csc, "(&(uid=%s)(|(&(objectClass=member)(|(term=%s)(term=%s)(nonMemberTerm=%s)(nonMemberTerm=%s)))(!(objectClass=member))))", username_escaped, cur_term, prev_term, cur_term, prev_term);

    /* issue CSC request */
    WARN_NEG1( msg_csc = ldap_search(ld_csc, PAM_CSC_CSC_BASE_DN,
        LDAP_SCOPE_SUBTREE, filter_csc, attrs_csc, 0) )

    /* wait for CSC response */
    WARN_NEG1( ldap_result(ld_csc, msg_csc, 1, &timeout, &res_csc) )

    /* check if we received an entry from CSC */
    if(ldap_count_entries(ld_csc, res_csc) == 0)
    {
        /* show notice and disallow login */
        pam_csc_print_message(pamh, PAM_CSC_EXPIRED_MSG, PAM_ERROR_MSG);
        syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_CSC_SYSLOG_EXPIRED_NO_TERMS,
            username);
        retval = (syscom ? PAM_SUCCESS : PAM_AUTH_ERR);
        goto cleanup;
    }

    /* get CSC entry */
    WARN_ZERO( entry = ldap_first_entry(ld_csc, res_csc) )
    values = ldap_get_values(ld_csc, entry, "term");
    nmvalues = ldap_get_values(ld_csc, entry, "nonMemberTerm");

    if(!values && !nmvalues)
    {
        syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_CSC_SYSLOG_NOT_A_MEMBER,
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
    if (nmvalues) {
        values_iter = nmvalues;
        while (*values_iter) {
            if (strcmp(*values_iter, cur_term) == 0) {
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
            pam_csc_print_message(pamh, PAM_CSC_EXPIRED_MSG, PAM_TEXT_INFO);
            syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_CSC_SYSLOG_EXPIRED_LAST_TERM,
                username);
        }
        else
        {
            /* show notice and disallow login */
            pam_csc_print_message(pamh, PAM_CSC_EXPIRED_MSG, PAM_ERROR_MSG);
            syslog(LOG_AUTHPRIV | LOG_NOTICE, PAM_CSC_SYSLOG_EXPIRED_NO_TERMS,
                username);
            retval = (syscom ? PAM_SUCCESS : PAM_AUTH_ERR);
        }
    }

cleanup:
    if(values) ldap_value_free(values);
    if(nmvalues) ldap_value_free(nmvalues);
    if(res_csc) ldap_msgfree(res_csc);
    if(ld_csc) ldap_unbind(ld_csc);
    if(filter_csc) free(filter_csc);
    if(username_escaped) free(username_escaped);
    return retval;
}

