using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using TMPro;
using UnityEngine.UI;

// GameUI 클래스는 UI 요소와 게임 로직 간의 상호작용을 관리합니다.
public class GameUI : MonoBehaviour
{
    [Header("#1 가위바위보 버튼 UI")]
    public Button rockButton;       // '바위' 버튼
    public Button paperButton;      // '보' 버튼
    public Button scissorsButton;   // '가위' 버튼

    [Header("#2 게임 결과 UI")]
    public TextMeshProUGUI resultText;        // 게임 결과를 표시하는 텍스트
    public TextMeshProUGUI serverChoiceText;  // 서버의 선택을 표시하는 텍스트
    public TextMeshProUGUI userChoiceText;    // 플레이어의 선택을 표시하는 텍스트

    [Header("#3 게임 매니저 및 랭킹 시스템")]
    public Button HistoryButton;    // 게임 히스토리 버튼
    public Button RankingButton;    // 랭킹 버튼

    // 게임과 관련된 매니저 클래스 참조
    private GameManager gameManager;               // 게임 로직을 처리하는 매니저
    private GameHistoryManager gameHistoryManager; // 게임 히스토리 데이터를 관리하는 매니저
    private RankingSystem rankingSystem;           // 랭킹 시스템을 관리하는 매니저

    // 게임 시작 시 초기화
    private void Start()
    {
        // 게임 매니저 및 관련 컴포넌트 초기화
        gameManager = GetComponent<GameManager>();
        gameHistoryManager = GetComponent<GameHistoryManager>();
        rankingSystem = GetComponent<RankingSystem>();

        // 버튼 클릭 이벤트에 리스너 등록
        rockButton.onClick.AddListener(() => OnRockButtonClick());
        paperButton.onClick.AddListener(() => OnPaperButtonClick());
        scissorsButton.onClick.AddListener(() => OnScissorsButtonClick());
        HistoryButton.onClick.AddListener(() => OnHistoryButtonClick());
        RankingButton.onClick.AddListener(() => OnRankingButtonClick());
    }

    // '바위' 버튼 클릭 시 호출
    private void OnRockButtonClick() => StartCoroutine(PlayGameCoroutine("rock"));

    // '보' 버튼 클릭 시 호출
    private void OnPaperButtonClick() => StartCoroutine(PlayGameCoroutine("paper"));

    // '가위' 버튼 클릭 시 호출
    private void OnScissorsButtonClick() => StartCoroutine(PlayGameCoroutine("scissors"));

    // 히스토리 버튼 클릭 시 호출
    private void OnHistoryButtonClick() => StartCoroutine(GetHistoryCoroutine());

    // 랭킹 버튼 클릭 시 호출
    private void OnRankingButtonClick() => StartCoroutine(GetRankingCoroutine());

    // 선택한 가위바위보를 서버에 전송하고 결과를 처리하는 코루틴
    private IEnumerator PlayGameCoroutine(string choice)
    {
        yield return gameManager.PostPlayGame(choice); // 선택한 데이터를 서버로 전송
    }

    // 게임 히스토리를 서버에서 가져오는 코루틴
    private IEnumerator GetHistoryCoroutine()
    {
        yield return gameHistoryManager.GetHistory(); // 히스토리 데이터 요청
    }

    // 랭킹 데이터를 서버에서 가져오는 코루틴
    private IEnumerator GetRankingCoroutine()
    {
        yield return rankingSystem.FetchRanking(); // 랭킹 데이터 요청
    }
}