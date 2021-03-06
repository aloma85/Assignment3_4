"""empty message

Revision ID: fb6095da00e4
Revises: 4378b22a1f0e
Create Date: 2021-03-14 22:35:33.888487

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fb6095da00e4'
down_revision = '4378b22a1f0e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('notes', sa.Column('body', sa.String(length=255), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('notes', 'body')
    # ### end Alembic commands ###
