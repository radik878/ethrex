window.BENCHMARK_DATA = {
  "lastUpdate": 1759059456095,
  "repoUrl": "https://github.com/radik878/ethrex",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1ef53ccda5fd3f96118cadbd296fbff6e5c10b22",
          "message": "ci(l2): free space in lint workflow (#4671)\n\n**Motivation**\n\nOur lint workflow is failing with a `No space left on device` error.\n\n**Description**\n\nAdds the `Free Disk Space` step that we already use in other workflows.\n\nCloses None",
          "timestamp": "2025-09-26T20:34:59Z",
          "tree_id": "ba81c83559f1ec6e7cfb26511f31cf4b80e99c47",
          "url": "https://github.com/radik878/ethrex/commit/1ef53ccda5fd3f96118cadbd296fbff6e5c10b22"
        },
        "date": 1759059454347,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 90599043973,
            "range": "± 726118719",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}