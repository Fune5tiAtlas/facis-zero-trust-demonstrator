@platform
Feature: Delivery pipeline security
  The demonstrator applies its own zero-trust posture to the delivery machine.
  Annex A row ZT-56 asks that every third-party action is pinned to a commit SHA
  and that no pipeline run holds a wildcard write scope.

  @ZT-56 @BDD-ZT-056
  Scenario: Every workflow is pinned to a commit and scoped to what it needs
    Given the repository workflows
    When the workflow hygiene check runs
    Then it reports no unpinned action and no wildcard write scope
