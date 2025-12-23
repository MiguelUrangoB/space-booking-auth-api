# Git Guide - Troubleshooting

## Missing Commits (¿Dónde están los commits?)

If you clone this repository and notice that commits are missing from the git history, it's likely because you have a **shallow clone**.

### Problem
A shallow clone only fetches a limited commit history, which can result in:
- Missing commits in `git log`
- Commits marked as "grafted"
- Incomplete project history

### Solution
To fetch the complete commit history, run:

```bash
git fetch --unshallow
```

This command will:
1. Download all missing commits from the remote repository
2. Convert your shallow clone into a full clone
3. Make the entire project history available

### Verification
After running the command, verify all commits are visible:

```bash
git log --oneline --all --graph
```

You should now see the complete commit history including:
- Initial commit with JWT authentication setup
- Swagger documentation commit
- All subsequent commits

### Prevention
When cloning in the future, avoid shallow clones by using:

```bash
git clone https://github.com/MiguelUrangoB/space-booking-auth-api.git
```

If you need a shallow clone for specific reasons (e.g., CI/CD, limited storage), be aware that you can always unshallow it later using the command above.
