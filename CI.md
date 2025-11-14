# Continuous Integration

In order to build the project automatically in GitHub follow these steps:

1. Fork the project
2. In your fork select the "Settings" option
3. On the left, expand "Secrets and variables"
4. Select "Actions"
5. Choose the "Variables" tab
6. Create the following "repository variables":
   1. `CR_OWNER` - the value of this should be what's before the slash in the GitHub repository name, either your GitHub username or the name of the organization which owns the repository
   2. `CR_REGISTRY` - the container registry to push to, in this case ghcr.io for the GitHub Container Registry
   3. `CR_USER` - the user who owns the Personal Access Token with rights to upload the container (likely your GitHub username, this might be the same as `CR_OWNER` if this repo is not part of an organization)
7. Click on the "Secrets" tab
8. In another tab or browser window, open the [Classic Personal Access Tokens](https://github.com/settings/tokens) settings page (for more information on this process you can see GitHub's [Creating a personal access token (classic)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic) guidance).
9. Click "Generate a new token" and choose "Generate a new token (classic)"
10. Put something meaningful in the note (such as: _Project name_ deployment token)
11. Choose an expiration date - you'll have to create a new token and update the value in the repo as frequently as you select here. "No expiration" is obviously most convenient and least secure.
12. For scopes, select the following:
    1. `repo`
    2. `write:packages`
    3. `read:packages`
    4. `delete:packages`
13. Choose "Generate token"
14. Optionally: save the token in your secure password manager in case you lose it
15. Go back to your other tab/browser window and click "New repository secret"
16. Name this secret `CR_TOKEN` and put enter your token into the Secret box
17. Click "Add secret"
18. Kick off a manual workflow run:
    1. Navigate to the repo
    2. Click the "Actions" tab at the top
    3. Select the "ci" workflow from the left nav
    4. Click the "Run workflow" dropdown on the right
    5. Choose the green "Run workflow" button
19. Once the build has succeded it pushes a container into the GitHub Container Registry - though it may not be linked to the project. To link it:
    1. Navigate to your GitHub profile page (click your icon in the top right and choose "Profile")
    2. Choose the "Packages" tab at the top
    3. You should see a container registry named after the project, click it

