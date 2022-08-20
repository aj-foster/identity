defmodule Identity.Notifier.BambooTest do
  use Identity.DataCase, async: true
  use Bamboo.Test

  alias Identity.Notifier.Bamboo, as: BambooNotifier

  describe "confirm_email/2" do
    test "sends an email" do
      email = "new@example.com"
      url = "http://localhost:4000/email/ABCDEF"
      assert :ok = BambooNotifier.confirm_email(email, url)

      assert_delivered_email_matches(%{
        subject: "Confirm Your Email Address",
        to: [{nil, "new@example.com"}],
        html_body: html_body,
        text_body: text_body
      })

      assert html_body =~ url
      assert text_body =~ url
    end
  end

  describe "reset_password/2" do
    test "sends emails" do
      user = Factory.insert(:user)
      %{email: email_one} = Factory.insert(:email, user: user)
      %{email: email_two} = Factory.insert(:email, user: user)
      url = "http://localhost:4000/password/ABCDEF"
      assert :ok = BambooNotifier.reset_password(user, url)

      assert_delivered_email_matches(%{
        subject: "Finish Resetting Your Password",
        to: emails,
        html_body: html_body,
        text_body: text_body
      })

      assert MapSet.new(emails) == MapSet.new([{nil, email_one}, {nil, email_two}])
      assert html_body =~ url
      assert text_body =~ url
    end
  end
end
