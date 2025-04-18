export default defineNuxtConfig({
  modules: ['../src/module'],
  ssr: false,
  devtools: { enabled: true },

  devServer: {
    port: 7445
  },

  compatibilityDate: '2025-04-18',

  uaaa: {
    issuer: 'https://unifiedauth.pku.edu.cn',
    clientAppId: 'org.fedstack.uaaa_nuxt',
    serverAppId: 'org.fedstack.uaaa_nuxt',
    issuerAppId: 'uaaa'
  }
})
