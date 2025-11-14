"""Add url column to Notification

Revision ID: 2c58685c7c9c
Revises: 9d69bd89f3d2
Create Date: 2025-09-27 20:03:32.844996
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2c58685c7c9c'
down_revision = '9d69bd89f3d2'
branch_labels = None
depends_on = None


def upgrade():
    # Add the url column to notification table
    op.add_column('notification', sa.Column('url', sa.String(length=255), nullable=True))


def downgrade():
    # Remove the url column if rolling back
    op.drop_column('notification', 'url')
