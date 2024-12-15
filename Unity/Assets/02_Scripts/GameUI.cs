using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using TMPro;
using UnityEngine.UI;

public class GameUI : MonoBehaviour
{
    [Header("#1 가위바위보 버튼 UI")]
    public Button rockButton;
    public Button paperButton;
    public Button scissorsButton;

    [Header("#2 게임 결과 UI")]
    public TextMeshProUGUI resultText;
    public TextMeshProUGUI serverChoiceText;
    public TextMeshProUGUI userChoiceText;

    [Header("#3 게임 매니저 및 랭킹 시스템")]
    public Button HistoryButton;
    public Button RankingButton;


    private GameManager gameManager;
    private GameHistoryManager gameHistoryManager;
    private RankingSystem rankingSystem;


    private void Start()
    {
        gameManager = GetComponent<GameManager>();
        gameHistoryManager = GetComponent<GameHistoryManager>();
        rankingSystem = GetComponent<RankingSystem>();

        rockButton.onClick.AddListener(() => OnRockButtonClick());
        paperButton.onClick.AddListener(() => OnPaperButtonClick());
        scissorsButton.onClick.AddListener(() => OnScissorsButtonClick());
        HistoryButton.onClick.AddListener(() => OnHistoryButtonClick());
        RankingButton.onClick.AddListener(() => OnRankingButtonClick());
    }

    private void OnRockButtonClick() => StartCoroutine(PlayGameCoroutine("rock"));
    private void OnPaperButtonClick() => StartCoroutine(PlayGameCoroutine("paper"));
    private void OnScissorsButtonClick() => StartCoroutine(PlayGameCoroutine("scissors"));
    private void OnHistoryButtonClick() => StartCoroutine(GetHistoryCoroutine());
    private void OnRankingButtonClick() => StartCoroutine(GetRankingCoroutine());


    private IEnumerator PlayGameCoroutine(string choice)
    {
        yield return gameManager.PostPlayGame(choice);
    }

    private IEnumerator GetHistoryCoroutine()
    {
        yield return gameHistoryManager.GetHistory();
    }

    private IEnumerator GetRankingCoroutine()
    {
        yield return rankingSystem.FetchRanking();
    }

}
