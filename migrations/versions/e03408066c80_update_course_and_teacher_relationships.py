"""Update Course and Teacher relationships

Revision ID: e03408066c80
Revises: 90f2b7167313
Create Date: 2024-10-17 20:56:19.146505

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e03408066c80'
down_revision = '90f2b7167313'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('teachers', schema=None) as batch_op:
        batch_op.alter_column('name',
               existing_type=sa.VARCHAR(length=100),
               nullable=False)
        batch_op.alter_column('email',
               existing_type=sa.VARCHAR(length=120),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('teachers', schema=None) as batch_op:
        batch_op.alter_column('email',
               existing_type=sa.VARCHAR(length=120),
               nullable=True)
        batch_op.alter_column('name',
               existing_type=sa.VARCHAR(length=100),
               nullable=True)

    # ### end Alembic commands ###
