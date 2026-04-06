import { afterEach, expect, mock, test } from 'bun:test'

const originalEnv = {
  CLAUDE_CODE_USE_OPENAI: process.env.CLAUDE_CODE_USE_OPENAI,
  OPENAI_BASE_URL: process.env.OPENAI_BASE_URL,
  OPENAI_MODEL: process.env.OPENAI_MODEL,
  CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED:
    process.env.CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED,
  CLAUDE_CODE_EFFORT_LEVEL: process.env.CLAUDE_CODE_EFFORT_LEVEL,
}

afterEach(() => {
  mock.restore()
  process.env.CLAUDE_CODE_USE_OPENAI = originalEnv.CLAUDE_CODE_USE_OPENAI
  process.env.OPENAI_BASE_URL = originalEnv.OPENAI_BASE_URL
  process.env.OPENAI_MODEL = originalEnv.OPENAI_MODEL
  process.env.CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED =
    originalEnv.CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED
  process.env.CLAUDE_CODE_EFFORT_LEVEL = originalEnv.CLAUDE_CODE_EFFORT_LEVEL
})

async function importFreshModelModule() {
  return import(`../../utils/model/model.js?ts=${Date.now()}-${Math.random()}`)
}

async function captureStartupScreenOutput() {
  const writes: string[] = []
  const originalWrite = process.stdout.write.bind(process.stdout)
  const originalIsTTY = process.stdout.isTTY
  ;(globalThis as typeof globalThis & {
    MACRO?: { VERSION: string; DISPLAY_VERSION?: string }
  }).MACRO = {
    VERSION: 'test-version',
    DISPLAY_VERSION: 'test-version',
  }

  Object.defineProperty(process.stdout, 'isTTY', {
    value: true,
    configurable: true,
  })

  ;(
    process.stdout as typeof process.stdout & {
      write: typeof process.stdout.write
    }
  ).write = ((chunk: string | Uint8Array) => {
    writes.push(
      typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'),
    )
    return true
  }) as typeof process.stdout.write

  try {
    const { printStartupScreen } = await import(
      `../../components/StartupScreen.js?ts=${Date.now()}-${Math.random()}`
    )
    printStartupScreen()
  } finally {
    ;(
      process.stdout as typeof process.stdout & {
        write: typeof process.stdout.write
      }
    ).write = originalWrite as typeof process.stdout.write

    Object.defineProperty(process.stdout, 'isTTY', {
      value: originalIsTTY,
      configurable: true,
    })
  }

  return writes.join('')
}

test('opens the model picker without awaiting local model discovery refresh', async () => {
  process.env.CLAUDE_CODE_USE_OPENAI = '1'
  process.env.OPENAI_BASE_URL = 'http://127.0.0.1:8080/v1'
  process.env.OPENAI_MODEL = 'qwen2.5-coder-7b-instruct'

  let resolveDiscovery: (() => void) | undefined
  const discoverOpenAICompatibleModelOptions = mock(
    () =>
      new Promise<void>(resolve => {
        resolveDiscovery = resolve
      }),
  )

  mock.module('../../utils/model/openaiModelDiscovery.js', () => ({
    discoverOpenAICompatibleModelOptions,
  }))

  const { call } = await import(`./model.js?ts=${Date.now()}-${Math.random()}`)
  const result = await Promise.race([
    call(() => {}, {} as never, ''),
    new Promise(resolve => setTimeout(() => resolve('timeout'), 50)),
  ])

  resolveDiscovery?.()

  expect(result).not.toBe('timeout')
})

test('profile-managed env does not override a saved settings model', async () => {
  process.env.CLAUDE_CODE_USE_OPENAI = '1'
  process.env.OPENAI_BASE_URL = 'https://api.openai.com/v1'
  process.env.OPENAI_MODEL = 'gpt-5.4'
  process.env.CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED = '1'

  mock.module('../../utils/settings/settings.js', () => ({
    getSettings_DEPRECATED: () => ({ model: 'gpt-5.3-codex' }),
    getInitialSettings: () => ({ model: 'gpt-5.3-codex' }),
  }))

  const { getUserSpecifiedModelSetting, getMainLoopModel } =
    await importFreshModelModule()

  expect(getUserSpecifiedModelSetting()).toBe('gpt-5.3-codex')
  expect(getMainLoopModel()).toBe('gpt-5.3-codex')
})

test('explicit env still overrides settings when env is not profile-managed', async () => {
  process.env.CLAUDE_CODE_USE_OPENAI = '1'
  process.env.OPENAI_BASE_URL = 'https://api.openai.com/v1'
  process.env.OPENAI_MODEL = 'gpt-5.4'
  delete process.env.CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED

  mock.module('../../utils/settings/settings.js', () => ({
    getSettings_DEPRECATED: () => ({ model: 'gpt-5.3-codex' }),
    getInitialSettings: () => ({ model: 'gpt-5.3-codex' }),
  }))

  const { getUserSpecifiedModelSetting, getMainLoopModel } =
    await importFreshModelModule()

  expect(getUserSpecifiedModelSetting()).toBe('gpt-5.4')
  expect(getMainLoopModel()).toBe('gpt-5.4')
})

test('profile-managed env prefers settings for codex provider too', async () => {
  process.env.CLAUDE_CODE_USE_OPENAI = '1'
  process.env.OPENAI_BASE_URL = 'https://chatgpt.com/backend-api/codex'
  process.env.OPENAI_MODEL = 'gpt-5.4'
  process.env.CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED = '1'

  mock.module('../../utils/settings/settings.js', () => ({
    getSettings_DEPRECATED: () => ({ model: 'gpt-5.3-codex' }),
    getInitialSettings: () => ({ model: 'gpt-5.3-codex' }),
  }))

  const { getUserSpecifiedModelSetting, getMainLoopModel } =
    await importFreshModelModule()

  expect(getUserSpecifiedModelSetting()).toBe('gpt-5.3-codex')
  expect(getMainLoopModel()).toBe('gpt-5.3-codex')
})

test('startup screen uses saved settings model over profile-managed env', async () => {
  process.env.CLAUDE_CODE_USE_OPENAI = '1'
  process.env.OPENAI_BASE_URL = 'https://chatgpt.com/backend-api/codex'
  process.env.OPENAI_MODEL = 'gpt-5.4'
  process.env.CLAUDE_CODE_PROVIDER_PROFILE_ENV_APPLIED = '1'
  delete process.env.CLAUDE_CODE_EFFORT_LEVEL

  mock.module('../../utils/settings/settings.js', () => ({
    getSettings_DEPRECATED: () => ({ model: 'gpt-5.3-codex', effortLevel: 'medium' }),
    getInitialSettings: () => ({ model: 'gpt-5.3-codex', effortLevel: 'medium' }),
  }))

  const output = await captureStartupScreenOutput()

  expect(output).toContain('gpt-5.3-codex (medium)')
  expect(output).not.toContain('gpt-5.4 (high)')
})
