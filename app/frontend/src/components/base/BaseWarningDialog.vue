<script>
import { mapState, mapActions } from 'pinia';
import { useAuthStore } from '~/store/auth';
import BaseDialog from '~/components/base/BaseDialog.vue';

export default {
  name: 'BaseWarningDialog',
  components: {
    BaseDialog,
  },
  computed: {
    ...mapState(useAuthStore, ['showTokenExpiredWarningMSg']),
  },
  methods: {
    ...mapActions(useAuthStore, ['setTokenExpirationWarningDialog']),
  },
};
</script>
<template>
  <BaseDialog
    type="CONTINUE"
    :show-close-button="true"
    :width="'50%'"
    v-model="showTokenExpiredWarningMSg"
    @close-dialog="
      () => {
        setTokenExpirationWarningDialog({
          showTokenExpiredWarningMSg: false,
          resetToken: false,
        });
      }
    "
    @continue-dialog="
      () => {
        setTokenExpirationWarningDialog({
          showTokenExpiredWarningMSg: false,
          resetToken: true,
        });
      }
    "
  >
    <template #title><span>Session expiring</span></template>
    <template #text>
      <div class="text-display-4">
        Your session will expire soon and you will be signed out automatically.
      </div>
      <div class="text-display-3 mt-3">Do you want to stay signed in?</div>
    </template>
    <template #button-text-continue>
      <span>Confirm</span>
    </template>
  </BaseDialog>
</template>
