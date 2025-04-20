<template>
  <div>
    <div>Protected</div>
    <div>
      AppID: <code>{{ $auth.appId.value }}</code>
    </div>
    <div>
      UserID: <code>{{ $auth.userId.value }}</code>
    </div>
    <div>
      SecurityLevel: <code>{{ $auth.securityLevel.value }}</code>
    </div>
    <div>
      CurrentTokens:
      <pre v-text="JSON.stringify($auth.tokens.value, null, 2)"></pre>
    </div>
    <div>
      CachedTokens:
      <pre v-text="JSON.stringify($auth.cachedTokens.value, null, 2)"></pre>
    </div>
    <textarea v-model="appId" placeholder="Enter appId"></textarea>
    <button @click="getToken">Get Token</button>
    <div>
      Token:
      <code>{{ token }}</code>
    </div>
  </div>
</template>

<script setup lang="ts">
const { $auth } = useNuxtApp()

const appId = ref('')
const token = ref('')

async function getToken() {
  const result = await $auth.getAuthToken(appId.value)
  token.value = result?.token ?? 'Failed'
  console.log(result)
}
</script>
