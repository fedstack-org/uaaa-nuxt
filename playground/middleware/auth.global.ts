export default defineNuxtRouteMiddleware((to) => {
  // Allow access to auth routes
  if (to.path.startsWith('/auth')) return

  const { $auth } = useNuxtApp()
  if (!$auth.isLoggedIn.value) {
    return navigateTo({
      path: '/auth/login',
      query: { redirect: to.fullPath }
    })
  }
})
