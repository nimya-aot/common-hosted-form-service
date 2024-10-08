<script setup>
import { storeToRefs } from 'pinia';
import { computed, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';

import { useFormStore } from '~/store/form';

const { t, locale } = useI18n({ useScope: 'global' });

const properties = defineProps({
  inputHeaders: {
    type: Array,
    default: undefined,
  },
  // The data you will be filtering with
  inputData: {
    type: Array,
    default: undefined,
  },
  resetData: {
    type: Array,
    default: () => [],
  },
  // The default selected data
  preselectedData: {
    type: Array,
    default: () => [],
  },
  inputItemKey: {
    type: String,
    default: 'key',
  },
  inputFilterLabel: {
    type: String,
    default: '',
  },
  inputFilterPlaceholder: {
    type: String,
    default: undefined,
  },
  inputSaveButtonText: {
    type: String,
    default: undefined,
  },
});

const emit = defineEmits(['saving-filter-data', 'cancel-filter-data']);

const headers = properties.inputHeaders || [
  {
    title: t('trans.baseFilter.columnName'),
    align: 'start',
    sortable: true,
    key: 'title',
  },
];
const inputData = properties.inputData || [
  { title: t('trans.baseFilter.exampleText'), key: 'exampleText1' },
  { title: t('trans.baseFilter.exampleText2'), key: 'exampleText2' },
];
const inputFilter = ref('');
const inputFilterPlaceholder =
  properties.inputFilterPlaceholder || t('trans.baseFilter.exampleText2');
const inputSaveButtonText =
  properties.inputSaveButtonText || t('trans.baseFilter.filter');
const selectedData = ref([]);

const { isRTL } = storeToRefs(useFormStore());

const RTL = computed(() => (isRTL.value ? 'ml-3' : 'mr-3'));

function savingFilterData() {
  inputFilter.value = '';
  emit('saving-filter-data', selectedData.value);
}

function onResetColumns() {
  selectedData.value = properties.resetData;
  inputFilter.value = '';
}

function cancelFilterData() {
  (selectedData.value = properties.preselectedData), emit('cancel-filter-data');
}

onMounted(() => {
  selectedData.value = Object.freeze(properties.preselectedData);
});

defineExpose({ selectedData, inputFilter });
</script>

<template>
  <v-card :class="{ 'dir-rtl': isRTL }">
    <v-card-title class="text-h5 pb-0 titleWrapper">
      <slot name="filter-title"></slot>
    </v-card-title>
    <v-card-subtitle class="mt-1 d-flex subTitleWrapper">
      <slot name="filter-subtitle"></slot>
    </v-card-subtitle>
    <v-card-text class="mt-0 pt-0">
      <hr class="hr" />

      <div class="d-flex flex-row" style="gap: 10px">
        <v-text-field
          v-model="inputFilter"
          data-test="filter-search"
          :label="inputFilterLabel"
          :placeholder="inputFilterPlaceholder"
          clearable
          color="primary"
          prepend-inner-icon="search"
          variant="filled"
          density="compact"
          class="mt-3"
          :class="{ label: isRTL }"
          :lang="locale"
        >
        </v-text-field>
        <v-tooltip location="bottom">
          <template #activator="{ props }">
            <v-btn
              data-test="reset-columns-btn"
              color="primary"
              class="mx-1 align-self-center mb-3"
              icon
              v-bind="props"
              :title="$t('trans.baseFilter.resetColumns')"
              @click="onResetColumns"
            >
              <v-icon
                style="pointer-events: none"
                icon="mdi:mdi-repeat"
                size="xl"
              />
            </v-btn>
          </template>
          <span :lang="locale">{{ $t('trans.baseFilter.resetColumns') }}</span>
        </v-tooltip>
      </div>
      <v-data-table
        v-model="selectedData"
        data-test="filter-table"
        fixed-header
        show-select
        hide-default-footer
        height="300px"
        :headers="headers"
        :items="inputData"
        items-per-page="-1"
        :item-value="inputItemKey"
        :search="inputFilter"
        class="bg-grey-lighten-5 mb-3"
        disable-pagination
        :lang="locale"
      >
      </v-data-table>
      <v-btn
        data-test="save-btn"
        class="bg-primary mt-3"
        :lang="locale"
        :title="inputSaveButtonText"
        @click="savingFilterData"
      >
        {{ inputSaveButtonText }}
      </v-btn>
      <v-btn
        data-test="cancel-btn"
        class="mt-3 text-primary"
        :class="RTL"
        variant="outlined"
        :lang="locale"
        :title="$t('trans.baseFilter.cancel')"
        @click="cancelFilterData"
        >{{ $t('trans.baseFilter.cancel') }}</v-btn
      >
    </v-card-text>
  </v-card>
</template>

<style lang="scss" scoped>
.subTitleWrapper {
  font-style: normal !important;
  font-size: 18px !important;
  font-variant: normal !important;
  font-family: BCSans !important;
  font-weight: normal !important;
  color: #707070c1 !important;
  gap: 10px !important;
  padding-bottom: 0px !important;
  margin-bottom: 0px !important;
}
.titleWrapper {
  font-style: normal !important;
  font-size: 22px !important;
  font-weight: bold !important;
  font-variant: normal !important;
  font-family: BCSans !important;
  color: #000000 !important;
}
.hr {
  height: 1px;
  border: none;
  background-color: #707070c1;
  margin-bottom: 0px;
}
</style>
