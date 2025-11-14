"""Make last_checked nullable

Revision ID: b01113b0c255
Revises: a4f8f1ac2ba1
Create Date: 2025-09-29 21:14:14.297063
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b01113b0c255'
down_revision = 'a4f8f1ac2ba1'
branch_labels = None
depends_on = None


def upgrade():
    # ✅ Only alter column, do NOT drop tables
    op.alter_column(
        'phishing_urls',
        'last_checked',
        existing_type=sa.DateTime(),
        nullable=True
    )


def downgrade():
    # Roll back to NOT NULL
    op.alter_column(
        'phishing_urls',
        'last_checked',
        existing_type=sa.DateTime(),
        nullable=False
    )
