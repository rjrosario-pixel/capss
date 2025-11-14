"""Initial migration with reset_code

Revision ID: 9d69bd89f3d2
Revises: 
Create Date: 2025-08-03 17:30:03.307693
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '9d69bd89f3d2'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('reset_code', sa.String(length=6), nullable=True))
    op.add_column('users', sa.Column('reset_expiration', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('users', 'reset_expiration')
    op.drop_column('users', 'reset_code')
