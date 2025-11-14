"""Add last_checked column to phishing_urls

Revision ID: a4f8f1ac2ba1
Revises: 2c58685c7c9c
Create Date: 2025-09-28 20:33:42.776647

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a4f8f1ac2ba1'
down_revision = '2c58685c7c9c'
branch_labels = None
depends_on = None


def upgrade():
    # ✅ Only add the new column
    op.add_column('phishing_urls',
        sa.Column('last_checked', sa.DateTime(), nullable=True)
    )


def downgrade():
    # ✅ Remove the column if we downgrade
    op.drop_column('phishing_urls', 'last_checked')
