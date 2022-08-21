defmodule Identity.Token do
  @moduledoc """
  Provides helpers for working with revokable tokens.

  > #### Note {:.info}
  >
  > Functions in this module are used by the main `Identity` module and provided schemas. It is
  > unlikely that you will call these functions directly, unless you are reimplementing one of
  > the core functions.
  """

  @hash_algorithm :sha256
  @token_size_bytes 32

  @doc """
  Generate a random token.

  The data returned from this function is not encoded, so it may not be printable or URL-safe. All
  tokens have a length of #{@token_size_bytes} bytes.

  See `:crypto.strong_rand_bytes/1` for more information.
  """
  @spec generate_token :: binary
  def generate_token do
    :crypto.strong_rand_bytes(@token_size_bytes)
  end

  @doc """
  Hash a token.

  The data returned from this function is not encoded, so it may not be printable or URL-safe. All
  tokens are hashed using #{@hash_algorithm}.

  See `:crypto.hash/2` for more information.
  """
  @spec hash_token(binary) :: binary
  def hash_token(token) do
    :crypto.hash(@hash_algorithm, token)
  end

  @doc """
  Generate 10 human-readable 2FA backup codes.

  All of the codes returned by this function are base-32 encoded and 8 characters long. They all
  begin with a letter to help distinguish them from normal 2FA codes. There is a slight bias in
  the codes, as the letter `O` is always replaced by the letter `X` to avoid confusion with the
  number `0`.
  """
  @spec generate_backup_codes :: [String.t()]
  def generate_backup_codes do
    for letter <- Enum.take_random(?A..?Z, 10) do
      suffix =
        :crypto.strong_rand_bytes(5)
        |> Base.encode32()
        |> binary_part(0, 7)

      String.replace(<<letter, suffix::binary>>, "O", "X")
    end
  end
end
