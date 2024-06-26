<script setup>
import { i18n } from '~/internationalization';
import { useNotificationStore } from '~/store/notification';
import { NotificationTypes } from '~/utils/constants';

const properties = defineProps({
  buttonText: {
    type: String,
    default: '',
  },
  disabled: {
    type: Boolean,
    default: false,
  },
  textToCopy: {
    type: String,
    default: undefined,
  },
  snackBarText: {
    type: String,
    default: i18n.t('trans.baseCopyToClipboard.linkToClipboard'),
  },
  tooltipText: {
    type: String,
    default: i18n.t('trans.baseCopyToClipboard.copyToClipboard'),
  },
});

const emit = defineEmits(['copied']);

function onCopy() {
  emit('copied');
  const notificationStore = useNotificationStore();
  notificationStore.addNotification({
    text: properties.snackBarText,
    ...NotificationTypes.INFO,
  });
}

function onError(e) {
  const notificationStore = useNotificationStore();
  notificationStore.addNotification({
    text: i18n.t('trans.baseCopyToClipboard.errCopyToClipboard'),
    consoleError: e,
  });
}
</script>

<template>
  <span>
    <v-tooltip location="bottom">
      <template #activator="{ props }">
        <v-btn
          v-clipboard:copy="textToCopy"
          v-clipboard:success="onCopy"
          v-clipboard:error="onError"
          color="primary"
          :disabled="disabled"
          icon
          v-bind="props"
          size="x-small"
          :title="buttonText"
        >
          <v-icon icon="mdi:mdi-content-copy"></v-icon>
          <span v-if="buttonText">{{ buttonText }}</span>
        </v-btn>
      </template>
      <span>{{ tooltipText }}</span>
    </v-tooltip>
  </span>
</template>
