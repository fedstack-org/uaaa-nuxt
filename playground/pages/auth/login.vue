<template>
  <div>正在转向登录页面</div>
</template>

<script setup lang="ts">
const route = useRoute()
const { $auth } = useNuxtApp()

onMounted(async () => {
  const redirectTo = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
  const redirectUrl = await $auth.startLogin(redirectTo)
  location.href = redirectUrl
})
</script>
