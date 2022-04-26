defmodule Identity.Test.Repo.Migrations.AddIdentity do
  use Ecto.Migration

  def up, do: Identity.Migrations.up()
  def down, do: Identity.Migrations.down()
end
