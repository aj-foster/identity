defmodule Identity.ControllerTest do
  use Identity.ConnCase

  describe "new_session/2" do
    test "stuff", %{conn: conn} do
      get(conn, "/session/new")
    end
  end
end
