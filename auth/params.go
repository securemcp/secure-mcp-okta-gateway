package auth

func (a *Auth) GetBaseURL() string {
	return a.baseURL
}

func (a *Auth) GetDynamicRegistrationURL() string {
	return a.baseURL + "/auth/register"
}

func (a *Auth) GetAuthorizationURL() string {
	return a.baseURL + "/auth/authorize"
}

func (a *Auth) GetTokenURL() string {
	return a.baseURL + "/auth/token"
}

func (a *Auth) GetSupportTokenEndpointAuthMethods() []string {
	methods := make([]string, 0, len(a.supportedTokenEndpointAuthMethods))
	for m := range a.supportedTokenEndpointAuthMethods {
		methods = append(methods, m)
	}

	return methods
}

func (a *Auth) GetSupportGrantTypes() []string {
	types := make([]string, 0, len(a.supportedGrantTypes))
	for t := range a.supportedGrantTypes {
		types = append(types, t)
	}

	return types
}

func (a *Auth) GetSupportResponseTypes() []string {
	types := make([]string, 0, len(a.supportedResponseTypes))
	for t := range a.supportedResponseTypes {
		types = append(types, t)
	}

	return types
}

func (a *Auth) GetSupportCodeChallengeMethods() []string {
	methods := make([]string, 0, len(a.supportedCodeChallengeMethods))
	for m := range a.supportedCodeChallengeMethods {
		methods = append(methods, m)
	}

	return methods
}
