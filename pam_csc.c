#define PAM_SM_ACCOUNT
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <ldap.h>
#include <syslog.h>
#include <pwd.h>

#define PAM_CSC_LDAP_URI \
    "ldap://caffeine.csclub.uwaterloo.ca ldap://perpugilliam.csclub.uwaterloo.ca"
#define PAM_CSC_LDAP_USER_BASE_DN       "ou=People,dc=csclub,dc=uwaterloo,dc=ca"
#define PAM_CSC_LDAP_GROUP_BASE_DN      "ou=Group,dc=csclub,dc=uwaterloo,dc=ca"
#define PAM_CSC_LDAP_TIMEOUT            5
#define PAM_CSC_ALLOWED_GROUPS          "cn=staff"
#define PAM_CSC_MINIMUM_UID             1000
#define PAM_CSC_EXPIRED_MSG \
    "*****************************************************************************\n" \
    "*                                                                           *\n" \
    "*    Your account has expired - please contact the Computer Science Club    *\n" \
    "*                                                                           *\n" \
    "*****************************************************************************\n"

/*
 * User terms are defined as (3 * year + term) where term is:
 *   0 = Winter, 1 = Spring, 2 = Fall
 * Term is a string in the form [f|w|s][year]
 */

enum check_user_type_t
{
    check_user_exists,
    check_user_cur_term,
    check_user_prev_term,
    check_user_groups
};

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

char* escape_ldap_string(const char* src)
{
    char *dst, *dstPtr;
    int i;

    if(!(dst = malloc(2 * strlen(src) + 1)))
        return NULL;
    dstPtr = dst;

    for(i = 0; i < strlen(src); i++)
    {
        if(src[i] == '*' || src[i] == '(' || src[i] == ')' || src[i] == '\\')
        {
            dstPtr[0] = '\\';
            dstPtr++;
        }
        dstPtr[0] = src[i];
        dstPtr++;
    }
    dstPtr[0] = '\0';

    return dst;
}

int check_user(const char* username, enum check_user_type_t checkType)
{
    int retval = PAM_SUCCESS;
    time_t curTime;
    struct tm* localTime;
    int longTerm, year, term;
    LDAP* ld = NULL;
    static const char termChars[] = {'w', 's', 'f'};
    char* usernameEscaped = NULL;
    char* filter = NULL;
    char* attr[] = {"objectClass", NULL};
    struct timeval timeout = {PAM_CSC_LDAP_TIMEOUT, 0};
    LDAPMessage* res = NULL;
    char* baseDN = NULL;

    /* fail-safe for root */
    if(strcmp(username, "root") == 0)
    {
        return PAM_SUCCESS;
    }

    /* connect and bind */
    WARN_LDAP( ldap_initialize(&ld, PAM_CSC_LDAP_URI) )
    WARN_NEG1( ldap_simple_bind(ld, NULL, NULL) )

    WARN_ZERO( usernameEscaped = escape_ldap_string(username) );
    switch(checkType)
    {
    case check_user_exists:

        /* format filter */
        WARN_ZERO( filter = malloc(50 + strlen(usernameEscaped)) )
        sprintf(filter, "(uid=%s)", usernameEscaped);
        baseDN = PAM_CSC_LDAP_USER_BASE_DN;
        break;

    case check_user_prev_term:
    case check_user_cur_term:

        /* get term info and compute current and previous term */
        WARN_NEG1( curTime = time(NULL) )
        WARN_ZERO( localTime = localtime(&curTime) )
        longTerm = 3 * (1900 + localTime->tm_year) + (localTime->tm_mon / 4);
        if(checkType == check_user_prev_term)
            longTerm--;
        term = termChars[longTerm % 3];
        year = longTerm / 3;

        /* format filter */
        WARN_ZERO( filter = malloc(100 + strlen(usernameEscaped)) )
        sprintf(filter, "(&(uid=%s)(|(&(objectClass=member)(term=%c%d))(!(objectClass=member))))", 
            usernameEscaped, term, year);
        baseDN = PAM_CSC_LDAP_USER_BASE_DN;
        break;

    case check_user_groups:

        /* format filter */
        WARN_ZERO( filter = malloc(50 + strlen(PAM_CSC_ALLOWED_GROUPS) + strlen(usernameEscaped)) )
        sprintf(filter, "(&(objectClass=posixGroup)(%s)(memberUid=%s))", PAM_CSC_ALLOWED_GROUPS, usernameEscaped);
        baseDN = PAM_CSC_LDAP_GROUP_BASE_DN;
        break;
    }

    /* search */
    WARN_LDAP( ldap_search_st(ld, baseDN, LDAP_SCOPE_SUBTREE, filter, attr, 1, &timeout, &res) )
    if((term = ldap_count_entries(ld, res)) == 0)
        retval = PAM_AUTH_ERR;

cleanup:

    if(usernameEscaped) free(usernameEscaped);
    if(res) ldap_msgfree(res);
    if(filter) free(filter);
    if(ld) ldap_unbind(ld);

    return retval;
}

int print_pam_message(pam_handle_t* pamh, char* msg, int style)
{
    int retval = PAM_SUCCESS;
    struct pam_conv* pamConv;
    struct pam_message pamMessage;
    struct pam_message* pamMessages[1];
    struct pam_response* pamResponse;

    /* output message */
    WARN_PAM( pam_get_item(pamh, PAM_CONV, (const void**)&pamConv) )
    pamMessages[0] = &pamMessage;
    pamMessage.msg_style = style;
    pamMessage.msg = msg;
    WARN_PAM( pamConv->conv(1, (const struct pam_message**)pamMessages, 
        &pamResponse, pamConv->appdata_ptr) )

cleanup:

    return retval;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char* argv[])
{
    const char* username;
    struct passwd* pwd;

    /* determine username */
    if((pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) || !username)
    {
        return PAM_USER_UNKNOWN;
    }

    /* check uid */
    pwd = getpwnam(username);
    if(pwd && pwd->pw_uid < PAM_CSC_MINIMUM_UID)
    {
        return PAM_SUCCESS;
    }

    /* check if user exists in ldap */
    if(check_user(username, check_user_exists) == PAM_AUTH_ERR)
    {
        return PAM_SUCCESS;
    }

    /* check if user is registered for the current term */
    if(check_user(username, check_user_cur_term) == PAM_SUCCESS)
    {
        return PAM_SUCCESS;
    }

    /* check if user is registered for the previous term */
    if(check_user(username, check_user_prev_term) == PAM_SUCCESS)
    {
        /* show warning */
        syslog(LOG_AUTHPRIV | LOG_NOTICE, "(pam_csc): %s was not registered for current term but was registered for previous term - permitting login\n", username);
        print_pam_message(pamh, PAM_CSC_EXPIRED_MSG, PAM_TEXT_INFO);
        return PAM_SUCCESS;
    }

    /* check if user is in allowed groups */
    if(check_user(username, check_user_groups) == PAM_SUCCESS)
    {
        /* show warning */
        print_pam_message(pamh, PAM_CSC_EXPIRED_MSG, PAM_TEXT_INFO);
        syslog(LOG_AUTHPRIV | LOG_NOTICE, "(pam_csc): %s was not registered but was in allowed groups - permitting login\n", username);
        return PAM_SUCCESS;
    }

    /* account has expired - show prompt */
    print_pam_message(pamh, PAM_CSC_EXPIRED_MSG, PAM_ERROR_MSG);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "(pam_csc): %s was not registered and was not in allowed groups - denying login\n", username);

    return PAM_AUTH_ERR;
}
