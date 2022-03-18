# BitCoin Implementaion

using : python 3.6.2

you can check my summary in [my blog](https://justlog.tistory.com/tag/bitcoin).

### Run

I use anaconda (for venv) and vscode (IDE).

So, you can set venv like bellow.
```bash
$ conda create --name bitcoin --file environment.yml
```

You can check other vscode run script in .vscode/launch.json


And you can set testing view with .vscode/settings.json, bellow one is my example
```
{
  "python.defaultInterpreterPath": "~/opt/anaconda3/envs/bitcoin/bin/python",
  "python.testing.unittestArgs": [
    "-v",
    "-s",
    "./src",
    "-p",
    "*_test.py"
  ],
  "python.testing.unittestEnabled": true,
  "python.testing.pytestEnabled": false,
}
```

---

### Reference 

- [Programming Bitcoin](https://learning.oreilly.com/library/view/programming-bitcoin/9781492031482/)