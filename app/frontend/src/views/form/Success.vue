<script setup>
import { storeToRefs } from 'pinia';

import FormViewer from '~/components/designer/FormViewer.vue';
import RequestReceipt from '~/components/forms/RequestReceipt.vue';
import { useAuthStore } from '~/store/auth';
import { useFormStore } from '~/store/form';

defineProps({
  s: {
    type: String,
    required: true,
  },
});

const { email } = storeToRefs(useAuthStore());
const { form, isRTL, lang } = storeToRefs(useFormStore());
</script>

<template>
  <div>
    <FormViewer :submission-id="s" :read-only="true" display-title>
      <template #alert>
        <div class="mb-5" :class="{ 'dir-rtl': isRTL }">
          <h1 class="mb-5" :lang="lang">
            <v-icon
              size="large"
              color="success"
              icon="mdi:mdi-check-circle"
            ></v-icon>
            {{ $t('trans.sucess.sucessFormSubmissn') }}
          </h1>
          <div v-if="form.showSubmissionConfirmation">
            <h3>
              <span class="d-print-none" :lang="lang">
                {{ $t('trans.sucess.keepRecord') }}{{ ' ' }}
              </span>
              <span :lang="lang">
                {{ $t('trans.sucess.confirmationId') }}:
                <mark>{{ s.substring(0, 8).toUpperCase() }}</mark>
              </span>
            </h3>
            <RequestReceipt
              class="d-print-none"
              :email="email"
              :form-name="form.name"
              :submission-id="s"
            />
          </div>
          <hr />
        </div>
      </template>
    </FormViewer>
  </div>
</template>
