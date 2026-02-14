"""add_account_lockout_fields

Revision ID: a0556b7ecc3e
Revises: 20b240317022
Create Date: 2026-02-14 17:46:31.974722
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a0556b7ecc3e"
down_revision: Union[str, None] = "20b240317022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column(
            "failed_login_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column("user", sa.Column("locked_until", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("user", "locked_until")
    op.drop_column("user", "failed_login_attempts")
