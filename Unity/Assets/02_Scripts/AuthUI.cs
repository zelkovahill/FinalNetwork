using System.Collections;
using System.Collections.Generic;
using TMPro; // TextMeshPro를 사용하기 위한 네임스페이스
using UnityEngine;
using UnityEngine.UI; // UI 컨트롤을 위한 네임스페이스

// AuthUI 클래스는 사용자 인터페이스(UI)를 처리하고 AuthManager와 상호작용하는 역할을 합니다.
public class AuthUI : MonoBehaviour
{
    [Header("#1 인풋 UI")]
    // 사용자 이름과 비밀번호를 입력받는 필드
    public TMP_InputField usernameInput;
    public TMP_InputField passwordInput;

    [Header("#2 버튼 UI")]
    // 회원가입, 로그인, 로그아웃, 데이터 요청 버튼
    public Button registerButton;
    public Button loginButton;
    public Button logoutButton;
    public Button getDataButton;

    // 인증 관련 작업을 수행하는 AuthManager의 참조
    private AuthManager authManager;

    // Start 메서드: UI 초기화 및 버튼 클릭 이벤트 연결
    private void Start()
    {
        // 동일한 게임 오브젝트에 있는 AuthManager 컴포넌트 가져오기
        authManager = GetComponent<AuthManager>();

        // 버튼 클릭 이벤트에 핸들러 메서드 연결
        registerButton.onClick.AddListener(OnResisterClick);
        loginButton.onClick.AddListener(OnLoginClick);
        logoutButton.onClick.AddListener(OnLogoutClick);
        getDataButton.onClick.AddListener(OnGetDataClick);
    }

    // 회원가입 버튼 클릭 이벤트 핸들러
    private void OnResisterClick() => StartCoroutine(RegisterCorutine());

    // 로그인 버튼 클릭 이벤트 핸들러
    private void OnLoginClick() => StartCoroutine(LoginCorutine());

    // 로그아웃 버튼 클릭 이벤트 핸들러
    private void OnLogoutClick() => StartCoroutine(LogoutCorutine());

    // 보호된 데이터 요청 버튼 클릭 이벤트 핸들러
    private void OnGetDataClick() => StartCoroutine(GetDataCorutine());

    // 회원가입 코루틴: 입력된 사용자 이름과 비밀번호를 AuthManager의 Register 메서드로 전달
    private IEnumerator RegisterCorutine()
    {
        yield return authManager.Register(usernameInput.text, passwordInput.text);
    }

    // 로그인 코루틴: 입력된 사용자 이름과 비밀번호를 AuthManager의 Login 메서드로 전달
    private IEnumerator LoginCorutine()
    {
        yield return authManager.Login(usernameInput.text, passwordInput.text);
    }

    // 로그아웃 코루틴: AuthManager의 Logout 메서드 호출
    private IEnumerator LogoutCorutine()
    {
        yield return authManager.Logout();
    }

    // 보호된 데이터 요청 코루틴: AuthManager의 GetProtectedData 메서드 호출
    private IEnumerator GetDataCorutine()
    {
        yield return StartCoroutine(authManager.GetProtectedData());
    }
}