// Step definitions for the JavaScript side of the acceptance suite. They run
// under Cucumber.js and emit the same legacy cucumber-JSON the Go runner emits,
// so both merge into one report.
import { Given, When, Then } from '@cucumber/cucumber'
import { readFile, access } from 'node:fs/promises'
import assert from 'node:assert/strict'

const repoRoot = new URL('../../../', import.meta.url)

Given('the repository documentation', async function () {
  await access(new URL('docs/', repoRoot))
  await access(new URL('mkdocs.yml', repoRoot))
})

When('the documentation site is assembled', async function () {
  // The site is assembled from mkdocs.yml: a page that is not in the navigation
  // is not published, however well written it is.
  this.navigation = await readFile(new URL('mkdocs.yml', repoRoot), 'utf8')
})

Then('the demonstrator usage manual is included in it', async function () {
  await access(new URL('docs/usage.md', repoRoot))
  assert.match(
    this.navigation,
    /usage\.md/,
    'docs/usage.md exists but is not in the mkdocs navigation, so it would not be published',
  )
})
