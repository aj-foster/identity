defmodule Identity.Notifier.SwooshTest do
  use Identity.DataCase, async: true
  import Swoosh.TestAssertions

  alias Identity.Notifier.Swoosh, as: SwooshNotifier

  describe "confirm_email/2" do
    test "sends an email" do
      email = "new@example.com"
      url = "http://localhost:4000/email/ABCDEF"
      assert :ok = SwooshNotifier.confirm_email(email, url)

      assert_email_sent(fn email ->
        assert email.subject == "Confirm Your Email Address"
        assert email.to == [{"", "new@example.com"}]
        assert email.html_body =~ url
        assert email.text_body =~ url
      end)
    end
  end

  describe "reset_password/2" do
    test "sends emails" do
      user = Factory.insert(:user)
      %{email: email_one} = Factory.insert(:email, user: user)
      %{email: email_two} = Factory.insert(:email, user: user)
      url = "http://localhost:4000/password/ABCDEF"
      assert :ok = SwooshNotifier.reset_password(user, url)

      assert_email_sent(fn email ->
        assert email.subject == "Finish Resetting Your Password"
        assert MapSet.new(email.to) == MapSet.new([{"", email_one}, {"", email_two}])
        assert email.html_body =~ url
        assert email.text_body =~ url
      end)
    end
  end
end
