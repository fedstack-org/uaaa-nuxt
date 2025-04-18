<template>
  <div />
</template>

<script setup lang="ts">
const route = useRoute()
const router = useRouter()
const { $auth } = useNuxtApp()

onMounted(async () => {
  const code = typeof route.query.code === 'string' ? route.query.code : ''
  const state = typeof route.query.state === 'string' ? route.query.state : ''
  try {
    const redirectUrl = await $auth.finishLogin(code, state)
    router.replace(redirectUrl)
  } catch (err) {
    console.error(err)
    alert('登录失败: ' + err)
  }
})
</script>
