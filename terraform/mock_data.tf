# ─── MOCK DATA FOR DEMO PURPOSES ─────────────────────────────────────────────

resource "aws_iam_user" "mock_auditor" {
  name = "mock-auditor-1"
  path = "/system/"
}

resource "aws_iam_user" "mock_developer" {
  name = "mock-developer-1"
  path = "/system/"
}

resource "aws_iam_group" "mock_group" {
  name = "mock-readonly-group"
}

resource "aws_iam_user_group_membership" "mock_membership" {
  user = aws_iam_user.mock_auditor.name
  groups = [
    aws_iam_group.mock_group.name,
  ]
}
