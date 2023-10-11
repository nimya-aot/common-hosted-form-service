import { defineStore } from 'pinia';
import getRouter from '~/router';
import { useIdle, useTimestamp, watchPausable } from '@vueuse/core';
import { ref } from 'vue';
import moment from 'moment';

/**
 * @function hasRoles
 * Checks if all elements in `roles` array exists in `tokenRoles` array
 * @param {string[]} tokenRoles An array of roles that exist in the token
 * @param {string[]} roles An array of roles to check
 * @returns {boolean} True if all `roles` exist in `tokenRoles`; false otherwise
 */
function hasRoles(tokenRoles, roles = []) {
  return roles
    .map((r) => tokenRoles.some((t) => t === r))
    .every((x) => x === true);
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    keycloak: undefined,
    redirectUri: undefined,
    ready: false,
    authenticated: false,
    showTokenExpiredWarningMSg: false,
    inActiveCheckInterval: null,
    updateTokenInterval: null,
    watchPausable: null,
  }),
  getters: {
    createLoginUrl: (state) => (options) =>
      state.keycloak.createLoginUrl(options),
    createLogoutUrl: (state) => (options) =>
      state.keycloak.createLogoutUrl(options),
    updateToken: (state) => (minValidity) =>
      state.keycloak.updateToken(minValidity),
    clearToken: (state) => () => state.keycloak.clearToken(),
    email: (state) =>
      state.keycloak.tokenParsed ? state.keycloak.tokenParsed.email : '',
    fullName: (state) => state.keycloak.tokenParsed.name,
    /**
     * Checks if the state has the required resource roles
     * @returns (T/F) Whether the state has the required roles
     */
    hasResourceRoles: (state) => {
      return (resource, roles) => {
        if (!state.authenticated) return false;
        if (!roles.length) return true; // No roles to check against

        if (state.resourceAccess && state.resourceAccess[resource]) {
          return hasRoles(state.resourceAccess[resource].roles, roles);
        }
        return false; // There are roles to check, but nothing in token to check against
      };
    },
    identityProvider: (state) =>
      state.keycloak.tokenParsed
        ? state.keycloak.tokenParsed.identity_provider
        : null,
    isAdmin: (state) => state.hasResourceRoles('chefs', ['admin']),
    isUser: (state) => state.hasResourceRoles('chefs', ['user']),
    keycloakSubject: (state) => state.keycloak.subject,
    identityProviderIdentity: (state) => state.keycloak.tokenParsed.idp_userid,
    moduleLoaded: (state) => !!state.keycloak,
    realmAccess: (state) => state.keycloak.tokenParsed.realm_access,
    resourceAccess: (state) => state.keycloak.tokenParsed.resource_access,
    token: (state) => state.keycloak.token,
    tokenParsed: (state) => state.keycloak.tokenParsed,
    userName: (state) => state.keycloak.tokenParsed.preferred_username,
    user: (state) => {
      const user = {
        username: '',
        firstName: '',
        lastName: '',
        fullName: '',
        email: '',
        idp: 'public',
        public: !state.authenticated,
      };
      if (state.authenticated) {
        if (state.tokenParsed.idp_username) {
          user.username = state.tokenParsed.idp_username;
        } else {
          user.username = state.tokenParsed.preferred_username;
        }
        user.firstName = state.tokenParsed.given_name;
        user.lastName = state.tokenParsed.family_name;
        user.fullName = state.tokenParsed.name;
        user.email = state.tokenParsed.email;
        user.idp = state.tokenParsed.identity_provider;
      }

      return user;
    },
  },
  actions: {
    updateKeycloak(keycloak, isAuthenticated) {
      this.keycloak = keycloak;
      this.authenticated = isAuthenticated;
    },
    login(idpHint) {
      if (this.ready) {
        if (!this.redirectUri) this.redirectUri = location.toString();

        const options = {
          redirectUri: this.redirectUri,
        };

        // Determine idpHint based on input or form
        if (idpHint && typeof idpHint === 'string') options.idpHint = idpHint;

        if (options.idpHint) {
          // Redirect to Keycloak if idpHint is available
          window.location.replace(this.createLoginUrl(options));
        } else {
          // Navigate to internal login page if no idpHint specified
          const router = getRouter();
          router.replace({
            name: 'Login',
            query: { idpHint: ['idir', 'bceid-business', 'bceid-basic'] },
          });
        }
      }
    },
    logout() {
      if (this.ready) {
        window.location.replace(
          this.createLogoutUrl({
            redirectUri: location.origin,
          })
        );
      }
    },
    async setTokenExpirationWarningDialog({
      showTokenExpiredWarningMSg,
      resetToken,
    }) {
      if (!showTokenExpiredWarningMSg && resetToken) {
        this.watchPausable.resume();
        this.updateToken(-1).catch(() => {
          this.clearToken();
          this.logout();
        });
      } else if (!resetToken) {
        clearInterval(this.updateTokenInterval);
        clearInterval(this.inActiveCheckInterval);
        this.logout();
      }
      this.showTokenExpiredWarningMSg = showTokenExpiredWarningMSg;
      if (showTokenExpiredWarningMSg) {
        setTimeout(() => {
          this.logout();
        }, 180000);
      }
    },
    async checkTokenExpiration() {
      if (this.authenticated) {
        const { idle, lastActive } = useIdle(1000, { initialState: true });
        const source = ref(idle);
        const now = useTimestamp({ interval: 1000 });
        this.watchPausable = watchPausable(source, (value) => {
          if (value) {
            console.log('I am that');
            clearInterval(this.updateTokenInterval);
            this.inActiveCheckInterval = setInterval(() => {
              let end = moment(now.value);
              let active = moment(lastActive.value);
              let duration = moment.duration(end.diff(active)).as('minutes');
              if (duration > 1) {
                this.watchPausable.pause();
                this.setTokenExpirationWarningDialog({
                  showTokenExpiredWarningMSg: true,
                  resetToken: true,
                });
              }
            }, 120000);
          } else {
            console.log('I am there');
            clearInterval(this.inActiveCheckInterval);
            this.updateTokenInterval = setInterval(() => {
              this.updateToken(-1).catch(() => {
                this.clearToken();
              });
            }, 240000);
          }
        });
        this.watchPausable.resume();
      }
    },
  },
});
