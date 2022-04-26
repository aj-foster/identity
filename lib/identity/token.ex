defmodule Identity.Token do
  @moduledoc "Provides helpers for working with revokable tokens."

  @hash_algorithm :sha256
  @token_size_bytes 32

  @doc "Generate a random token (not encoded)"
  @spec generate_token :: binary
  def generate_token do
    :crypto.strong_rand_bytes(@token_size_bytes)
  end

  @doc "Hash a token (not encoded)"
  @spec hash_token(binary) :: binary
  def hash_token(token) do
    :crypto.hash(@hash_algorithm, token)
  end

  @doc "Generate 10 human-readable backup codes"
  @spec generate_backup_codes :: [String.t()]
  def generate_backup_codes do
    for letter <- Enum.take_random(?A..?Z, 10) do
      suffix =
        :crypto.strong_rand_bytes(5)
        |> Base.encode32()
        |> binary_part(0, 7)

      # The first digit is always a letter so we can distinguish
      # in the UI between 6 digit TOTP codes and backup ones.
      # We also replace the letter O by X to avoid confusion with zero.
      String.replace(<<letter, suffix::binary>>, "O", "X")
    end
  end
end
