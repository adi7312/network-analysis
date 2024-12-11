# Network analysis tool


```
pip install -r requirements.txt
```

```
python3 nids.py --help
```


---

| **ID**   | **Category**        | **Type**     | **Status** | **Opis**                                                  |
| -------- | ------------------- | ------------ | ---------- | --------------------------------------------------------- |
| **A.1**  | Analiza flow        | Must-have    | Done       | Loading PCAP with NFStream                                |
| **A.2**  | Analiza flow        | Must-have    | Done       | Flow statistics                                           |
| **D.1**  | Detection as a Code | Must-have    | Done       | Detection with python. **TBD: Test with scapy/tcpreplay** |
| **D.2**  | Detection as a Code | Must-have    | Done       | Detection with pySigma                                    |
| **ML.1** | Machine Learning    | Must-have    | Done       | Model - visualisation of learning model                   |
| **ML.2** | Machine Learning    | Must-have    | Done       | Metrics - FPR, TPR, Confusion Matrix                      |
| **ML.3** | Machine Learning    | Nice-to-have | Done       | User can upload new data                                  |
| **E.1**  | Enrichment          | Must-have    | Done       | Alert enrichment                                          |
| **V.1**  | Wizualizacja        | Must-have    | Done       | Visualisaion of detected threats                          |
| **V.2**  | Wizualizacja        | Nice-to-have | Done       | Localisation visualistaion                                |