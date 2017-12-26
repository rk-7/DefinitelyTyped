// Type definitions for okta-sdk-nodejs 0.4
// Project: https://github.com/okta/okta-sdk-nodejs
// Definitions by: rk-7 <https://github.com/rk-7>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// TypeScript Version: 2.2

export namespace factories {
    class ApplicationFactory extends ModelResolutionFactory {
        getMapping(): {
            'AUTO_LOGIN': typeof models.AutoLoginApplication,
            'BASIC_AUTH': typeof models.BasicAuthApplication,
            'BOOKMARK': typeof models.BookmarkApplication,
            'BROWSER_PLUGIN': BrowserPluginApplication,
            'OPENID_CONNECT': typeof models.OpenIdConnectApplication,
            'SAML_2_0': typeof models.SamlApplication,
            'SECURE_PASSWORD_STORE': typeof models.SecurePasswordStoreApplication,
            'WS_FEDERATION': typeof models.WsFederationApplication,
        };
        getResolutionProperty(): string;
    }
    class BrowserPluginApplicationFactory extends ModelResolutionFactory {
        getMapping(): {
            'template_swa': typeof models.SwaApplication,
            'template_swa3field': typeof models.SwaThreeFieldApplication,
        };
        getResolutionProperty(): string;
    }
    class FactorFactory extends ModelResolutionFactory {
        getMapping(): {
            'call': typeof models.CallFactor,
            'email': typeof models.EmailFactor,
            'push': typeof models.PushFactor,
            'question': typeof models.SecurityQuestionFactor,
            'sms': typeof models.SmsFactor,
            'token': typeof models.TokenFactor,
            'token:hardware': typeof models.HardwareFactor,
            'token:software:totp': typeof models.TotpFactor,
            'web': typeof models.WebFactor,
        };
        getResolutionProperty(): string;
    }
    export { ApplicationFactory as Application };
    export { BrowserPluginApplicationFactory as BrowserPluginApplication };
    export { FactorFactory as Factor };
}
export namespace models {
    class Application extends Resource {
        _embedded: { [key: string]: any };
        _links: { [key: string]: any };
        accessibility: ApplicationAccessibility;
        created: Date;
        credentials: ApplicationCredentials;
        features: string[];
        id: string;
        label: string;
        lastUpdated: Date;
        licensing: ApplicationLicensing;
        name: string;
        settings: ApplicationSettings;
        signOnMode: ApplicationSignOnMode;
        status: string;
        visibility: ApplicationVisibility;
        constructor(resourceJson: any, client: Client);
        update(): Promise<Resource | ModelResolutionFactory>;
        delete(): Request;
        activate(): Request;
        deactivate(): Request;
        listApplicationUsers(queryParameters?: any): Collection;
        assignUserToApplication(appUser: AppUser): Promise<AppUser>;
        getApplicationUser(userId: string, queryParameters: any): Promise<AppUser>;
        createApplicationGroupAssignment(groupId: string, applicationGroupAssignment: ApplicationGroupAssignment): Promise<ApplicationGroupAssignment>;
        getApplicationGroupAssignment(groupId: string, queryParameters: any): Promise<ApplicationGroupAssignment>;
        generateApplicationKey(queryParameters: any): Promise<JsonWebKey>;
        cloneApplicationKey(keyId: string, queryParameters: any): Promise<JsonWebKey>;
        getApplicationKey(keyId: string): Promise<JsonWebKey>;
        listGroupAssignments(queryParameters: any): Collection;
        listKeys(): Collection;
    }
    class ApplicationAccessibility extends Resource {
        errorRedirectUrl: string;
        loginRedirectUrl: string;
        selfService: boolean;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationCredentials extends Resource {
        signing: ApplicationCredentialsSigning;
        userNameTemplate: ApplicationCredentialsUsernameTemplate;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationCredentialsOAuthClient extends Resource {
        autoKeyRotation: boolean;
        client_id: string;
        client_secret: string;
        token_endpoint_auth_method: OAuthEndpointAuthenticationMethod;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationCredentialsScheme extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationCredentialsSigning extends Resource {
        kid: string;
        lastRotated: Date;
        nextRotation: Date;
        rotationMode: string;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationCredentialsUsernameTemplate extends Resource {
        suffix: string;
        template: string;
        type: string;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationGroupAssignment extends Resource {
        _embedded: { [key: string]: any };
        _links: { [key: string]: any };
        id: string;
        lastUpdated: Date;
        priority: number;
        profile: UserProfile;
        constructor(resourceJson: any, client: Client);
        delete(appId: string): Request;
    }
    class ApplicationLicensing extends Resource {
        seatCount: number;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationSettings extends Resource {
        app: ApplicationSettingsApplication;
        notifications: ApplicationSettingsNotifications;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationSettingsApplication extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationSettingsNotifications extends Resource {
        vpn: ApplicationSettingsNotificationsVpn;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationSettingsNotificationsVpn extends Resource {
        helpUrl: string;
        message: string;
        network: ApplicationSettingsNotificationsVpnNetwork;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationSettingsNotificationsVpnNetwork extends Resource {
        connection: string;
        exclude: string[];
        include: string[];
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationSignOnMode extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationVisibility extends Resource {
        appLinks: { [key: string]: boolean };
        autoSubmitToolbar: boolean;
        hide: ApplicationVisibilityHide;
        constructor(resourceJson: any, client: Client);
    }
    class ApplicationVisibilityHide extends Resource {
        iOS: boolean;
        web: boolean;
        constructor(resourceJson: any, client: Client);
    }
    class AppLink extends Resource {
        appAssignmentId: string;
        appInstanceId: string;
        appName: string;
        credentialsSetup: boolean;
        hidden: boolean;
        id: string;
        label: string;
        linkUrl: string;
        logoUrl: string;
        sortOrder: number;
        constructor(resourceJson: any, client: Client);
    }
    class AppUser extends Resource {
        _embedded: any;
        _links: any;
        created: Date;
        credentials: AppUserCredentials;
        externalId: string;
        id: string;
        lastSync: Date;
        lastUpdated: Date;
        passwordChanged: Date;
        profile: UserProfile;
        scope: string;
        status: string;
        statusChanged: Date;
        syncState: string;
        constructor(resourceJson: any, client: Client);
        update(appId: string): Promise<AppUser>;
        delete(appId: string): Promise<AppUser>;
    }
    class AppUserCredentials extends Resource {
        password: AppUserPasswordCredential;
        userName: string;
        constructor(resourceJson: any, client: Client);
    }
    class AppUserPasswordCredential extends Resource {
        value: string;
        constructor(resourceJson: any, client: Client);
    }
    class AuthenticationProvider extends Resource {
        name: string;
        type: AuthenticationProviderType;
        constructor(resourceJson: any, client: Client);
    }
    class AuthenticationProviderType extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class AutoLoginApplication extends Application {
        credentials: SchemeApplicationCredentials;
        settings: AutoLoginApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class AutoLoginApplicationSettings extends ApplicationSettings {
        signOn: AutoLoginApplicationSettingsSignOn;
        constructor(resourceJson: any, client: Client);
    }
    class AutoLoginApplicationSettingsSignOn extends Resource {
        loginUrl: string;
        redirectUrl: string;
        constructor(resourceJson: any, client: Client);
    }
    class BasicApplicationSettings extends ApplicationSettings {
        app: BasicApplicationSettingsApplication;
        constructor(resourceJson: any, client: Client);
    }
    class BasicApplicationSettingsApplication extends ApplicationSettingsApplication {
        authURL: string;
        url: string;
        constructor(resourceJson: any, client: Client);
    }
    class BasicAuthApplication extends Application {
        credentials: SchemeApplicationCredentials;
        name: string;
        settings: BasicApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class BookmarkApplication extends Application {
        name: string;
        settings: BookmarkApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class BookmarkApplicationSettings extends ApplicationSettings {
        app: BookmarkApplicationSettingsApplication;
        constructor(resourceJson: any, client: Client);
    }
    class BookmarkApplicationSettingsApplication extends ApplicationSettingsApplication {
        requestIntegration: boolean;
        url: string;
        constructor(resourceJson: any, client: Client);
    }
    class BrowserPluginApplication extends Application {
        credentials: SchemeApplicationCredentials;
        constructor(resourceJson: any, client: Client);
    }
    class CallFactor extends Factor {
        profile: CallFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class CallFactorProfile extends FactorProfile {
        phoneExtension: string;
        phoneNumber: string;
        constructor(resourceJson: any, client: Client);
    }
    class ChangePasswordRequest extends Resource {
        newPassword: PasswordCredential;
        oldPassword: PasswordCredential;
        constructor(resourceJson: any, client: Client);
    }
    class CreateSessionRequest extends Resource {
        sessionToken: string;
        constructor(resourceJson: any, client: Client);
    }
    class EmailFactor extends Factor {
        profile: EmailFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class EmailFactorProfile extends FactorProfile {
        email: string;
        constructor(resourceJson: any, client: Client);
    }
    class Factor extends Resource {
        _embedded: string;
        _links: string;
        device: string;
        deviceType: string;
        factorType: FactorType;
        id: string;
        mfaStateTokenId: string;
        profile: FactorProfile;
        provider: FactorProvider;
        rechallengeExistingFactor: boolean;
        sessionId: string;
        status: FactorStatus;
        userId: string;
        constructor(resourceJson: any, client: Client);
        delete(userId: string): Request;
        activate(userId: string, verifyFactorRequest: VerifyFactorRequest): Promise<Factor>;
        verify(userId: string, verifyFactorRequest: VerifyFactorRequest, queryParameters: any): Promise<VerifyFactorResponse>;
    }
    class FactorProfile extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class FactorProvider extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class FactorResultType extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class FactorStatus extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class FactorType extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class ForgotPasswordResponse extends Resource {
        resetPasswordUrl: string;
        constructor(resourceJson: any, client: Client);
    }
    class Group extends Resource {
        _embedded: string;
        _links: string;
        created: Date;
        id: string;
        lastMembershipUpdated: Date;
        lastUpdated: Date;
        objectClass: string[];
        profile: GroupProfile;
        type: string;
        constructor(resourceJson: any, client: Client);
        update(): Promise<Group>;
        delete(): Request;
        removeUser(userId: string): Request;
        listUsers(queryParameters: any): Collection;
    }
    class GroupProfile extends Resource {
        description: string;
        name: string;
        constructor(resourceJson: any, client: Client);
    }
    class GroupRule extends Resource {
        actions: GroupRuleAction;
        conditions: GroupRuleConditions;
        created: Date;
        id: string;
        lastUpdated: Date;
        name: string;
        status: GroupRuleStatus;
        type: string;
        constructor(resourceJson: any, client: Client);
        update(): Promise<GroupRule>;
        delete(queryParameters: any): Request;
        activate(): Request;
        deactivate(): Request;
    }
    class GroupRuleAction extends Resource {
        assignUserToGroups: GroupRuleGroupAssignment;
        constructor(resourceJson: any, client: Client);
    }
    class GroupRuleConditions extends Resource {
        expression: GroupRuleExpression;
        people: GroupRulePeopleCondition;
        constructor(resourceJson: any, client: Client);
    }
    class GroupRuleExpression extends Resource {
        type: string;
        value: string;
        constructor(resourceJson: any, client: Client);
    }
    class GroupRuleGroupAssignment extends Resource {
        groupIds: string[];
        constructor(resourceJson: any, client: Client);
    }
    class GroupRuleGroupCondition extends Resource {
        exclude: string[];
        include: string[];
        constructor(resourceJson: any, client: Client);
    }
    class GroupRulePeopleCondition extends Resource {
        groups: GroupRuleGroupCondition;
        users: GroupRuleUserCondition;
        constructor(resourceJson: any, client: Client);
    }
    class GroupRuleStatus extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class GroupRuleUserCondition extends Resource {
        exclude: string[];
        include: string[];
        constructor(resourceJson: any, client: Client);
    }
    class GroupStats extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class HardwareFactor extends Factor {
        profile: HardwareFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class HardwareFactorProfile extends FactorProfile {
        credentialId: string;
        constructor(resourceJson: any, client: Client);
    }
    class JsonWebKey extends Resource {
        alg: string;
        created: Date;
        e: string;
        expiresAt: Date;
        key_ops: string[];
        kid: string;
        kty: string;
        lastUpdated: Date;
        n: string;
        status: string;
        use: string;
        x5c: string[];
        x5t: string;
        x5u: string;
        constructor(resourceJson: any, client: Client);
    }
    class OAuthApplicationCredentials extends ApplicationCredentials {
        oauthClient: ApplicationCredentialsOAuthClient;
        constructor(resourceJson: any, client: Client);
    }
    class OAuthEndpointAuthenticationMethod extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class OAuthGrantType extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class OAuthResponseType extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class OpenIdConnectApplication extends Application {
        credentials: OAuthApplicationCredentials;
        name: any;
        settings: OpenIdConnectApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class OpenIdConnectApplicationConsentMethod extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class OpenIdConnectApplicationSettings extends ApplicationSettings {
        oauthClient: OpenIdConnectApplicationSettingsClient;
        constructor(resourceJson: any, client: Client);
    }
    class OpenIdConnectApplicationSettingsClient extends Resource {
        application_type: OpenIdConnectApplicationType;
        client_uri: string;
        consent_method: OpenIdConnectApplicationConsentMethod;
        grant_types: any[];
        logo_uri: string;
        policy_uri: string;
        redirect_uris: any[];
        response_types: any[];
        tos_uri: string;
        constructor(resourceJson: any, client: Client);
    }
    class OpenIdConnectApplicationType extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class PasswordCredential extends Resource {
        value: string;
        constructor(resourceJson: any, client: Client);
    }
    class PushFactor extends Factor {
        profile: PushFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class PushFactorProfile extends FactorProfile {
        credentialId: string;
        deviceType: string;
        name: string;
        platform: string;
        version: string;
        constructor(resourceJson: any, client: Client);
    }
    class RecoveryQuestionCredential extends Resource {
        answer: string;
        question: string;
        constructor(resourceJson: any, client: Client);
    }
    class ResetPasswordToken extends Resource {
        resetPasswordUrl: string;
        constructor(resourceJson: any, client: Client);
    }
    class Role extends Resource {
        _embedded: string;
        created: Date;
        description: string;
        id: string;
        label: string;
        lastUpdated: Date;
        status: RoleStatus;
        type: string;
        constructor(resourceJson: any, client: Client);
    }
    class RoleStatus extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class SamlApplication extends Application {
        settings: SamlApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class SamlApplicationSettings extends ApplicationSettings {
        signOn: SamlApplicationSettingsSignOn;
        constructor(resourceJson: any, client: Client);
    }
    class SamlApplicationSettingsSignOn extends Resource {
        assertionSigned: boolean;
        attributeStatements: any[];
        audience: string;
        audienceOverride: string;
        authnContextClassRef: string;
        defaultRelayState: string;
        destination: string;
        destinationOverride: string;
        digestAlgorithm: string;
        honorForceAuthn: boolean;
        idpIssuer: string;
        recipient: string;
        recipientOverride: string;
        requestCompressed: boolean;
        responseSigned: boolean;
        signatureAlgorithm: string;
        spIssuer: string;
        ssoAcsUrl: string;
        ssoAcsUrlOverride: string;
        subjectNameIdFormat: string;
        subjectNameIdTemplate: string;
        constructor(resourceJson: any, client: Client);
    }
    class SamlAttributeStatement extends Resource {
        name: string;
        namespace: string;
        type: string;
        values: any[];
        constructor(resourceJson: any, client: Client);
    }
    class SchemeApplicationCredentials extends ApplicationCredentials {
        password: PasswordCredential;
        revealPassword: boolean;
        scheme: ApplicationCredentialsScheme;
        signing: ApplicationCredentialsSigning;
        userName: string;
        constructor(resourceJson: any, client: Client);
    }
    class SecurePasswordStoreApplication extends Application {
        credentials: SchemeApplicationCredentials;
        name: string;
        settings: SecurePasswordStoreApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class SecurePasswordStoreApplicationSettings extends ApplicationSettings {
        app: SecurePasswordStoreApplicationSettingsApplication;
        constructor(resourceJson: any, client: Client);
    }
    class SecurePasswordStoreApplicationSettingsApplication extends ApplicationSettingsApplication {
        optionalField1: string;
        optionalField1Value: string;
        optionalField2: string;
        optionalField2Value: string;
        optionalField3: string;
        optionalField3Value: string;
        passwordField: string;
        url: string;
        usernameField: string;
        constructor(resourceJson: any, client: Client);
    }
    class SecurityQuestion extends Resource {
        answer: string;
        question: string;
        questionText: string;
        constructor(resourceJson: any, client: Client);
    }
    class SecurityQuestionFactor extends Factor {
        profile: SecurityQuestionFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class SecurityQuestionFactorProfile extends FactorProfile {
        answer: string;
        question: string;
        questionText: string;
        constructor(resourceJson: any, client: Client);
    }
    class Session extends Resource {
        _links: string;
        amr: any[];
        createdAt: Date;
        expiresAt: Date;
        id: string;
        idp: SessionIdentityProvider;
        lastFactorVerification: Date;
        lastPasswordVerification: Date;
        login: string;
        status: SessionStatus;
        userId: string;
        constructor(resourceJson: any, client: Client);
        delete(): Request;
        refresh(): Promise<Session>;
    }
    class SessionAuthenticationMethod extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class SessionIdentityProvider extends Resource {
        id: string;
        type: SessionIdentityProviderType;
        constructor(resourceJson: any, client: Client);
    }
    class SessionIdentityProviderType extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class SessionStatus extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class SmsFactor extends Factor {
        profile: SmsFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class SmsFactorProfile extends FactorProfile {
        phoneNumber: string;
        constructor(resourceJson: any, client: Client);
    }
    class SwaApplication extends BrowserPluginApplication {
        name: string;
        settings: SwaApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class SwaApplicationSettings extends ApplicationSettings {
        app: SwaApplicationSettingsApplication;
        constructor(resourceJson: any, client: Client);
    }
    class SwaApplicationSettingsApplication extends ApplicationSettingsApplication {
        buttonField: string;
        loginUrlRegex: string;
        passwordField: string;
        url: string;
        usernameField: string;
        constructor(resourceJson: any, client: Client);
    }
    class SwaThreeFieldApplication extends BrowserPluginApplication {
        name: string;
        settings: SwaThreeFieldApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class SwaThreeFieldApplicationSettings extends ApplicationSettings {
        app: SwaThreeFieldApplicationSettingsApplication;
        constructor(resourceJson: any, client: Client);
    }
    class SwaThreeFieldApplicationSettingsApplication extends ApplicationSettingsApplication {
        buttonSelector: string;
        extraFieldSelector: string;
        extraFieldValue: string;
        loginUrlRegex: string;
        passwordSelector: string;
        targetUrl: string;
        userNameSelector: string;
        constructor(resourceJson: any, client: Client);
    }
    class TempPassword extends Resource {
        tempPassword: string;
        constructor(resourceJson: any, client: Client);
    }
    class TokenFactor extends Factor {
        profile: TokenFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class TokenFactorProfile extends FactorProfile {
        credentialId: string;
        constructor(resourceJson: any, client: Client);
    }
    class TotpFactor extends Factor {
        profile: TotpFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class TotpFactorProfile extends FactorProfile {
        credentialId: string;
        constructor(resourceJson: any, client: Client);
    }
    class User extends Resource {
        _embedded: string;
        _links: string;
        activated: Date;
        created: Date;
        credentials: UserCredentials;
        id: string;
        lastLogin: Date;
        lastUpdated: Date;
        passwordChanged: Date;
        profile: UserProfile;
        status: UserStatus;
        statusChanged: Date;
        transitioningToStatus: UserStatus;
        constructor(resourceJson: any, client: Client);
        update(): Promise<User>;
        delete(): Request;
        endAllSessions(queryParameters: any): Request;
        listAppLinks(queryParameters: any): Collection;
        changePassword(changePasswordRequest: ChangePasswordRequest): Promise<UserCredentials>;
        changeRecoveryQuestion(userCredentials: UserCredentials): Promise<UserCredentials>;
        forgotPassword(userCredentials: UserCredentials, queryParameters: any): Promise<ForgotPasswordResponse>;
        listRoles(queryParameters: any): Collection;
        addRole(role: Role): Promise<Role>;
        removeRole(roleId: string): Request;
        listGroupTargetsForRole(roleId: string, queryParameters: any): Collection;
        removeGroupTargetFromRole(roleId: string, groupId: string): Request;
        addGroupTargetToRole(roleId: string, groupId: string): Request;
        listGroups(queryParameters: any): Collection;
        activate(queryParameters: any): Promise<UserActivationToken>;
        deactivate(): Request;
        suspend(): Request;
        unsuspend(): Request;
        resetPassword(queryParameters: any): Promise<ResetPasswordToken>;
        expirePassword(queryParameters: any): Promise<TempPassword>;
        unlock(): Request;
        resetFactors(): Request;
        addToGroup(groupId: string): Request;
        addFactor(factor: Factor, queryParameters: any): Promise<Factor>;
        listSupportedFactors(): Collection;
        listFactors(): Collection;
        listSupportedSecurityQuestions(): Collection;
        getFactor(factorId: string): Promise<Factor>;
    }
    class UserActivationToken extends Resource {
        activationToken: string;
        activationUrl: string;
        constructor(resourceJson: any, client: Client);
    }
    class UserCredentials extends Resource {
        password: PasswordCredential;
        provider: AuthenticationProvider;
        recovery_question: RecoveryQuestionCredential;
        constructor(resourceJson: any, client: Client);
    }
    class UserProfile extends Resource {
        [key: string]: any;
        email: string;
        firstName: string;
        lastName: string;
        login: string;
        mobilePhone: string;
        secondEmail: string;
        constructor(resourceJson: any, client: Client);
    }
    class UserStatus extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class Verify extends Resource {
        constructor(resourceJson: any, client: Client);
    }
    class VerifyFactorRequest extends Resource {
        activationToken: string;
        answer: string;
        nextPassCode: string;
        passCode: string;
        constructor(resourceJson: any, client: Client);
    }
    class VerifyFactorResponse extends Resource {
        _embedded: string;
        _links: string;
        expiresAt: Date;
        factorResult: FactorResultType;
        factorResultMessage: string;
        constructor(resourceJson: any, client: Client);
    }
    class WebFactor extends Factor {
        profile: WebFactorProfile;
        constructor(resourceJson: any, client: Client);
    }
    class WebFactorProfile extends FactorProfile {
        credentialId: string;
        constructor(resourceJson: any, client: Client);
    }
    class WsFederationApplication extends Application {
        settings: WsFederationApplicationSettings;
        constructor(resourceJson: any, client: Client);
    }
    class WsFederationApplicationSettings extends ApplicationSettings {
        app: WsFederationApplicationSettingsApplication;
        constructor(resourceJson: any, client: Client);
    }
    class WsFederationApplicationSettingsApplication extends ApplicationSettingsApplication {
        attributeStatements: string;
        audienceRestriction: string;
        authnContextClassRef: string;
        groupFilter: string;
        groupName: string;
        groupValueFormat: string;
        nameIDFormat: string;
        realm: string;
        siteURL: string;
        usernameAttribute: string;
        wReplyOverride: boolean;
        wReplyURL: string;
        constructor(resourceJson: any, client: Client);
    }
}
export class ConfigLoader {
    prefix: string;
    config: { client: { orgUrl: string, token: string } };
    constructor();
    applyDefaults(): void;
    applyEnvVars(): void;
    applyYamlFile(path: string): void;
    apply(config: any): void;
}
/**
 * @description Coerce a generic HTTP error into an Error object that is easy to grok.
 */
export class HttpError extends Error {
    url: string;
    status: number | string;
    responseBody: string;
    constructor(url: string, status: number | string, responseBody: string);
}
export class ErrorCause extends Resource {
    summary: string;
}
export class OktaApiError extends Error {
    constructor(url: string, status: number | string, responseBody: object);
    errorCode: number;
    errorSummary: string;
    errorCauses: ErrorCause[];
    errorLink: any;
    errorId: string;
    url: string;
}
export class ModelFactory<T> {
    constructor(Ctor: new (...args: any[]) => T);
    createInstance(resource: Resource, client: Client): any;
}
export function OktaResponseHeaders(responseHeadersMap: any): { [key: string]: any };
export class ModelResolutionFactory {
    getMapping(): object;
    getResolutionProperty(): string;
    createInstance(resource: Resource, client: Client): Resource | ModelResolutionFactory;
}
export class Resource {
    client: Client;
    [key: string]: any;
    constructor(resourceJson: any, client: Client);
}
export class Collection {
    nextUri: string;
    factory: any;
    client: Client;
    currentItems: any[];
    constructor(client: Client, uri: string, factory: any);
    next(): Promise<{ value: any, done: boolean }>;
    getNextPage(): Promise<any>;
    each(iterator: (...prams: any[]) => any): Promise<any>;
}
export class GeneratedApiClient {
    /**
     * @description
     * Enumerates apps added to your organization with pagination. A subset of apps can be returned that match a supported filter expression or query.
     */
    listApplications(queryParameters?: any): Collection;
    /**
     * @description
     * Adds a new application to your Okta organization.
     */
    createApplication(application: models.Application, queryParameters?: any): Promise<Resource | ModelResolutionFactory>;
    /**
     *
     * @description
     * Removes an inactive application.
     */
    deleteApplication(appId: string): Request;
    /**
     *
     * @description
     * Fetches an application from your Okta organization by `id`.
     */
    getApplication(appId: string, queryParameters?: any): Promise<Resource | ModelResolutionFactory>;
    /**
     *
     * @description
     * Updates an application in your organization.
     */
    updateApplication(appId: string, application: models.Application): Promise<Resource | ModelResolutionFactory>;
    /**
     *
     * @description
     * Enumerates key credentials for an application
     */
    listApplicationKeys(appId: string): Collection;
    /**
     *
     * @description
     * Generates a new X.509 certificate for an application key credential
     */
    generateApplicationKey(appId: string, queryParameters?: any): Promise<JsonWebKey>;
    /**
     *
     * @description
     * Gets a specific [application key credential](#application-key-credential-model) by `kid`
     */
    getApplicationKey(appId: string, keyId: string): Promise<JsonWebKey>;
    /**
     *
     * @description
     * Clones a X.509 certificate for an application key credential from a source application to target application.
     */
    cloneApplicationKey(appId: string, keyId: string, queryParameters?: any): Promise<JsonWebKey>;
    /**
     *
     * @description
     * Enumerates group assignments for an application.
     */
    listApplicationGroupAssignments(appId: string, queryParameters?: any): Collection;
    /**
     *
     * @description
     * Removes a group assignment from an application.
     */
    deleteApplicationGroupAssignment(appId: string, groupId: string): Request;
    /**
     *
     * @description
     * Fetches an application group assignment
     */
    getApplicationGroupAssignment(appId: string, groupId: string, queryParameters?: any): Promise<models.ApplicationGroupAssignment>;
    /**
     *
     * @description
     * Assigns a group to an application
     */
    createApplicationGroupAssignment(appId: string, groupId: string, applicationGroupAssignment: models.ApplicationGroupAssignment): Promise<models.ApplicationGroupAssignment>;
    /**
     *
     * @description
     * Activates an inactive application.
     */
    activateApplication(appId: string): Request;
    /**
     *
     * @description
     * Deactivates an active application.
     */
    deactivateApplication(appId: string): Request;
    /**
     *
     * @description
     * Enumerates all assigned [application users](#application-user-model) for an application.
     */
    listApplicationUsers(appId: string, queryParameters?: any): Collection;
    /**
     *
     * @description
     * Assigns an user to an application with [credentials](#application-user-credentials-object)
     * and an app-specific [profile](#application-user-profile-object).
     * Profile mappings defined for the application are first applied before applying any profile properties specified in the request.
     */
    assignUserToApplication(appId: string, appUser: models.AppUser): Promise<models.AppUser>;
    /**
     *
     * @description
     * Removes an assignment for a user from an application.
     */
    deleteApplicationUser(appId: string, userId: string): Request;
    /**
     *
     * @description
     * Fetches a specific user assignment for application by `id`.
     */
    getApplicationUser(appId: string, userId: string, queryParameters?: any): Promise<models.AppUser>;
    /**
     *
     * @description
     * Updates a user's profile for an application
     */
    updateApplicationUser(appId: string, userId: string, appUser: models.AppUser): Promise<models.AppUser>;
    /**
     * @description
     * Enumerates groups in your organization with pagination.
     * A subset of groups can be returned that match a supported filter expression or query.
     */
    listGroups(queryParameters?: any): Collection;
    /**
     * @description
     * Adds a new group with `OKTA_GROUP` type to your organization.
     */
    createGroup(group: models.Group): Promise<models.Group>;
    /**
     * @description
     * Lists all group rules for your organization.
     */
    listRules(queryParameters?: any): Collection;
    /**
     * @description
     * Creates a group rule to dynamically add users to the specified group if they match the condition
     */
    createRule(groupRule: models.GroupRule): Promise<models.GroupRule>;
    /**
     *
     * @description
     * Removes a specific group rule by id from your organization
     */
    deleteRule(ruleId: string, queryParameters?: any): Request;
    /**
     *
     * @description
     * Fetches a specific group rule by id from your organization
     */
    getRule(ruleId: string): Promise<models.GroupRule>;
    /**
     *
     * @description
     * Convenience method for /api/v1/groups/rules/{ruleId}
     */
    updateRule(ruleId: string, groupRule: models.GroupRule): Promise<models.GroupRule>;
    /**
     *
     * @description
     * Activates a specific group rule by id from your organization
     */
    activateRule(ruleId: string): Request;
    /**
     *
     * @description
     * Deactivates a specific group rule by id from your organization
     */
    deactivateRule(ruleId: string): Request;
    /**
     *
     * @description
     * Removes a group with `OKTA_GROUP` type from your organization.
     */
    deleteGroup(groupId: string): Request;
    /**
     *
     * @description
     * Lists all group rules for your organization.
     */
    getGroup(groupId: string, queryParameters?: any): Promise<models.Group>;
    /**
     *
     * @description
     * Updates the profile for a group with `OKTA_GROUP` type from your organization.
     */
    updateGroup(groupId: string, group: models.Group): Promise<models.Group>;
    /**
     *
     * @description
     * Enumerates all [users](/docs/api/resources/users.html#user-model) that are a member of a group.
     */
    listGroupUsers(groupId: string, queryParameters?: any): Collection;
    /**
     *
     * @description
     * Removes a [user](users.html#user-model) from a group with `OKTA_GROUP` type.
     */
    removeGroupUser(groupId: string, userId: string): Request;
    /**
     *
     * @description
     * Adds a [user](users.html#user-model) to a group with `OKTA_GROUP` type.
     */
    addUserToGroup(groupId: string, userId: string): Request;
    /**
     * @description
     * Creates a new session for a user with a valid session token.
     * Use this API if, for example, you want to set the session cookie yourself instead of allowing Okta to set it,
     * or want to hold the session ID in order to delete a session via the API instead of visiting the logout URL.
     */
    createSession(createSessionRequest: models.CreateSessionRequest): Promise<models.Session>;
    /**
     *
     * @description
     * Convenience method for /api/v1/sessions/{sessionId}
     */
    endSession(sessionId: string): Request;
    /**
     *
     * @description
     * Get details about a session.
     */
    getSession(sessionId: string): Promise<models.Session>;
    /**
     *
     * @description
     * Convenience method for /api/v1/sessions/{sessionId}/lifecycle/refresh
     */
    refreshSession(sessionId: string): Promise<models.Session>;
    /**
     * @description
     * Lists users in your organization with pagination in most cases.
     * A subset of users can be returned that match a supported filter expression or search criteria.
     */
    listUsers(queryParameters?: any): Collection;
    /**
     * @description
     * Creates a new user in your Okta organization with or without credentials.
     */
    createUser(user: models.User, queryParameters?: any): Promise<models.User>;
    /**
     * @description
     * Deletes a user permanently.
     * This operation can only be performed on users that have a `DEPROVISIONED` status.  **This action cannot be recovered!**
     */
    deactivateOrDeleteUser(userId: string): Request;
    /**
     * @description
     * Fetches a user from your Okta organization.
     */
    getUser(userId: string): Promise<models.User>;
    /**
     * @description
     * Update a user's profile and/or credentials using strict-update semantics.
     */
    updateUser(userId: string, user: models.User): Promise<models.User>;
    /**
     * @description
     * Fetches appLinks for all direct or indirect (via group membership) assigned applications.
     */
    listAppLinks(userId: string, queryParameters?: any): Collection;
    /**
     * @description
     * Changes a user's password by validating the user's current password.
     * This operation can only be performed on users in `STAGED`, `ACTIVE`, `PASSWORD_EXPIRED`,
     * or `RECOVERY` status that have a valid [password credential](#password-object)
     */
    changePassword(userId: string, changePasswordRequest: models.ChangePasswordRequest): Promise<models.UserCredentials>;
    /**
     * @description
     * Changes a user's recovery question & answer credential by validating the user's current password.
     * This operation can only be performed on users in **STAGED**, **ACTIVE** or **RECOVERY** `status`
     * that have a valid [password credential](#password-object)
     */
    changeRecoveryQuestion(userId: string, userCredentials: models.UserCredentials): Promise<models.UserCredentials>;
    /**
     * @description
     * Generates a one-time token (OTT) that can be used to reset a user's password.
     * The user will be required to validate their security question's answer when visiting the reset link.
     * This operation can only be performed on users with a valid [recovery question credential](#recovery-question-object)
     * and have an `ACTIVE` status.
     */
    forgotPassword(userId: string, userCredentials: models.UserCredentials, queryParameters?: any): Promise<models.ForgotPasswordResponse>;
    /**
     * @description
     * Enumerates all the enrolled factors for the specified user
     */
    listFactors(userId: string): Collection;
    /**
     * @description
     * Enrolls a user with a supported [factor](#list-factors-to-enroll)
     */
    addFactor(userId: string, factor: models.Factor, queryParameters?: any): Promise<models.Factor>;
    /**
     * @description
     * Enumerates all the [supported factors](#supported-factors-for-providers) that can be enrolled for the specified user
     */
    listSupportedFactors(userId: string): Collection;
    /**
     * @description
     * Enumerates all available security questions for a user's `question` factor
     */
    listSupportedSecurityQuestions(userId: string): Collection;
    /**
     * @description
     * Unenrolls an existing factor for the specified user, allowing the user to enroll a new factor.
     */
    deleteFactor(userId: string, factorId: string): Request;
    /**
     * @description
     * Fetches a factor for the specified user
     */
    getFactor(userId: string, factorId: string): Promise<models.Factor>;
    /**
     * @description
     * The `sms` and `token:software:totp` [factor types](#factor-type) require activation to complete the enrollment process.
     */
    activateFactor(userId: string, factorId: string, verifyFactorRequest: models.VerifyFactorRequest): Promise<models.Factor>;
    /**
     * @description
     * Verifies an OTP for a `token` or `token:hardware` factor
     */
    verifyFactor(userId: string, factorId: string, verifyFactorRequest: models.VerifyFactorRequest, queryParameters?: any): Promise<models.VerifyFactorResponse>;
    /**
     * @description
     * Fetches the groups of which the user is a member.
     */
    listUserGroups(userId: string, queryParameters?: any): Collection;
    /**
     * @description
     * Activates a user.  This operation can only be performed on users with a `STAGED` status.
     * Activation of a user is an asynchronous operation.  The user will have the `transitioningToStatus`
     * property with a value of `ACTIVE` during activation to indicate that the user hasn't completed the asynchronous operation.
     * The user will have a status of `ACTIVE` when the activation process is complete.
     */
    activateUser(userId: string, queryParameters?: any): Promise<models.UserActivationToken>;
    /**
     * @description
     * Deactivates a user.  This operation can only be performed on users that do not have a `DEPROVISIONED` status.
     * Deactivation of a user is an asynchronous operation.  The user will have the `transitioningToStatus`
     * property with a value of `DEPROVISIONED` during deactivation to indicate that the user hasn't completed the asynchronous operation.
     * The user will have a status of `DEPROVISIONED` when the deactivation process is complete.
     */
    deactivateUser(userId: string): Request;
    /**
     * @description
     * This operation transitions the user to the status of `PASSWORD_EXPIRED` so that the user is required to change
     * their password at their next login.
     */
    expirePassword(userId: string, queryParameters?: any): Promise<models.TempPassword>;
    /**
     * @description
     * This operation resets all factors for the specified user. All MFA factor enrollments returned
     * to the unenrolled state. The user's status remains ACTIVE. This link is present only
     * if the user is currently enrolled in one or more MFA factors.
     */
    resetAllFactors(userId: string): Request;
    /**
     * @description
     * Generates a one-time token (OTT) that can be used to reset a user's password.
     * The OTT link can be automatically emailed to the user or returned to the API caller and distributed using a custom flow.
     */
    resetPassword(userId: string, queryParameters?: any): Promise<models.ResetPasswordToken>;
    /**
     * @description
     * Suspends a user.  This operation can only be performed on users with an `ACTIVE` status.
     * The user will have a status of `SUSPENDED` when the process is complete.
     */
    suspendUser(userId: string): Request;
    /**
     * @description
     * Unlocks a user with a `LOCKED_OUT` status and returns them to `ACTIVE` status.
     * Users will be able to login with their current password.
     */
    unlockUser(userId: string): Request;
    /**
     * @description
     * Unsuspends a user and returns them to the `ACTIVE` state.
     * This operation can only be performed on users that have a `SUSPENDED` status.
     */
    unsuspendUser(userId: string): Request;
    /**
     * @description
     * Lists all roles assigned to a user.
     */
    listAssignedRoles(userId: string, queryParameters?: any): Collection;
    /**
     * @description
     * Assigns a role to a user.
     */
    addRoleToUser(userId: string, role: models.Role): Promise<models.Role>;
    /**
     * @description
     * Unassigns a role from a user.
     */
    removeRoleFromUser(userId: string, roleId: string): Request;
    /**
     * @description
     * Convenience method for /api/v1/users/{userId}/roles/{roleId}/targets/groups
     */
    listGroupTargetsForRole(userId: string, roleId: string, queryParameters?: any): Collection;
    /**
     * @description
     * Convenience method for /api/v1/users/{userId}/roles/{roleId}/targets/groups/{groupId}
     */
    removeGroupTargetFromRole(userId: string, roleId: string, groupId: string): Request;
    /**
     * @description
     * Convenience method for /api/v1/users/{userId}/roles/{roleId}/targets/groups/{groupId}
     */
    addGroupTargetToRole(userId: string, roleId: string, groupId: string): Request;
    /**
     * @description
     * Removes all active identity provider sessions. This forces the user to authenticate on
     * the next operation. Optionally revokes OpenID Connect and OAuth refresh and access tokens issued to the user.
     */
    endAllUserSessions(userId: string, queryParameters?: any): Request;
}
/**
 * Base client that encapsulates the HTTP request mechanism, and knowledge of how to authenticate with the Okta API
 *
 */
export class Client extends GeneratedApiClient {
    constructor(clientConfig: any);
}
