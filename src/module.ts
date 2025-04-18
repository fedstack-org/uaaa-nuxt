import { defineNuxtModule, addPlugin, createResolver } from '@nuxt/kit'
import { defu } from 'defu'

// Module options TypeScript interface definition
export interface ModuleOptions {
  issuer: string
  clientAppId: string
  serverAppId: string
  issuerAppId: string
}

export default defineNuxtModule<ModuleOptions>({
  meta: {
    name: '@uaaa/nuxt',
    configKey: 'uaaa'
  },
  // Default configuration options of the Nuxt module
  defaults: {},
  setup(options, nuxt) {
    const resolver = createResolver(import.meta.url)

    nuxt.options.runtimeConfig.public.uaaa = defu(nuxt.options.runtimeConfig.public.uaaa, {
      issuer: options.issuer,
      clientAppId: options.clientAppId,
      serverAppId: options.serverAppId,
      issuerAppId: options.issuerAppId
    })

    // Do not add the extension since the `.ts` will be transpiled to `.mjs` after `npm run prepack`
    addPlugin({
      src: resolver.resolve('./runtime/plugin'),
      mode: 'client'
    })
  }
})
