#!/user/env python3
# -*- coding: utf-8 -*-


""" client command """
C_PING_PONG = 'cmd/client/ping-pong'  # ping-pong
C_BROADCAST = 'cmd/client/broadcast'  # 全ノードに伝播
C_GET_PEER_INFO = 'cmd/client/get-peer-info'  # 隣接ノードの情報を取得
C_GET_PEERS = 'cmd/client/get-peers'  # ピアリストを取得
C_CHECK_REACHABLE = 'cmd/client/check-reachable'  # 外部からServerに到達できるかチェック
C_FILE_CHECK = 'cmd/client/file-check'  # Fileが存在するかHashをチェック
C_FILE_GET = 'cmd/client/file-get'  # Fileの転送を依頼
C_FILE_DELETE = 'cmd/client/file-delete'  # 全ノードからFileを消去
C_DIRECT_CMD = 'cmd/client/direct-cmd'  # 隣接ノードに直接CMDを打つ

