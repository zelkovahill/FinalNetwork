using System.Collections;
using System.Collections.Generic;
using TMPro;
using UnityEngine;
using UnityEngine.UI;

public class AuthUI : MonoBehaviour
{
    [Header("#1 인풋 UI")]
    public TMP_InputField usernameInput;
    public TMP_InputField passwordInput;

    [Header("#2 버튼 UI")]
    public Button registerButton;
    public Button loginButton;
    public Button logoutButton;
    public Button getDataButton;

    private AuthManager authManager;

    private void Start()
    {
        authManager = GetComponent<AuthManager>();

        registerButton.onClick.AddListener(OnResisterClick);
        loginButton.onClick.AddListener(OnLoginClick);
        logoutButton.onClick.AddListener(OnLogoutClick);
        getDataButton.onClick.AddListener(OnGetDataClick);
    }

    private void OnResisterClick() => StartCoroutine(RegisterCorutine());
    private void OnLoginClick() => StartCoroutine(LoginCorutine());
    private void OnLogoutClick() => StartCoroutine(LogoutCorutine());
    private void OnGetDataClick() => StartCoroutine(GetDataCorutine());

    private IEnumerator RegisterCorutine()
    {
        yield return authManager.Register(usernameInput.text, passwordInput.text);
    }

    private IEnumerator LoginCorutine()
    {
        yield return authManager.Login(usernameInput.text, passwordInput.text);
    }

    private IEnumerator LogoutCorutine()
    {
        yield return authManager.Logout();
    }

    private IEnumerator GetDataCorutine()
    {
        yield return StartCoroutine(authManager.GetProtectedData());
    }

}
