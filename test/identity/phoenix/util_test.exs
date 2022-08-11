defmodule Identity.Phoenix.UtilTest do
  use Identity.ConnCase, async: true

  alias Identity.Phoenix.Util

  describe "path_for/2" do
    test "returns the path for an identity route", %{conn: conn} do
      conn = get(conn, "/session/new")
      assert Util.path_for(conn, :new_session) == "/session/new"
    end

    test "raises for a non-existent route", %{conn: conn} do
      conn = get(conn, "/session/new")

      assert_raise RuntimeError, fn ->
        Util.path_for(conn, :invalid_route)
      end
    end
  end

  describe "path_for/3" do
    test "returns a path with parameters replaced", %{conn: conn} do
      conn = get(conn, "/session/new")
      assert Util.path_for(conn, :confirm_email, "my_token") == "/email/my_token"
    end
  end
end
