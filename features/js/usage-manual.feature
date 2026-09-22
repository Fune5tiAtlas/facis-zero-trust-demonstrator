@docs
Feature: Demonstrator usage documentation
  Annex A row ZT-17 asks that the demonstrator manual is generated from the
  repository rather than written by hand somewhere else, and that it is
  buildable from GitHub.

  @ZT-17 @BDD-ZT-017
  Scenario: The usage manual is part of the generated documentation site
    Given the repository documentation
    When the documentation site is assembled
    Then the demonstrator usage manual is included in it
