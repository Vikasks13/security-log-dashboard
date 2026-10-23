# OpenSSH Log Dataset

This directory contains sample authentication logs from an OpenSSH server, provided by the **Loghub** project.

## Dataset Details
- **File:** `OpenSSH_2k.log`
- **Total Lines:** 2,000 log records
- **Data Source:** [Loghub GitHub Repository](https://github.com/logpai/loghub)
- **Loghub Subdirectory:** [OpenSSH](https://github.com/logpai/loghub/tree/master/OpenSSH)

## Description
The logs were collected from an OpenSSH server over a period of 28+ days in an academic lab environment (`LabSZ`). The dataset contains authentic operational system activity including:
- `Failed password` events (both invalid users and known usernames)
- `Invalid user` probe attempts (dictionary scans)
- `Accepted password` / `Accepted publickey` successful sessions
- Pre-auth disconnections, reverse DNS mapping warnings, and PAM daemon messages

## Citation
If you utilize this dataset in academic work or research, please cite:
```bibtex
@inproceedings{zhu2023loghub,
  title={Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics},
  author={Zhu, Jieming and He, Shilin and He, Pinjia and Liu, Jinyang and Lyu, Michael R.},
  booktitle={IEEE International Symposium on Software Reliability Engineering (ISSRE)},
  year={2023}
}
```

## License
The dataset is distributed under the terms of the Loghub Project License:
> The datasets are freely available for research or academic work, subject to the following condition: For any usage or distribution of the loghub datasets, please refer to the loghub repository URL (https://github.com/logpai/loghub) and cite the loghub paper where applicable.
