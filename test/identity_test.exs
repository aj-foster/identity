defmodule IdentityTest do
  use ExUnit.Case
  doctest Identity

  test "greets the world" do
    assert Identity.hello() == :world
  end
end
