#!/user/env python3
# -*- coding: utf-8 -*-


""" channel command """
C_PING_PONG = 'cmd/ch/ping-pong'  # ping-pongを返す
C_JOIN = 'cmd/ch/join'  # channelにJOINする
C_LEAVE = 'cmd/ch/leave'  # channelからLEAVEする
C_ADD_NEW_MEMBER = 'cmd/ch/add-new-member'  # channelにMemberを加える
C_ADD_NEW_KEY = 'cmd/ch/add-new-key'  # channelの共通鍵を加える
C_RUN_FOR_MASTER = 'cmd/ch/run-for-master'  # Masterがいない為、立候補する
C_VOTE_CANDIDATE = 'cmd/ch/reject-candidate'  # 立候補者をランクが低い為拒否する
C_MESSAGE = 'cmd/ch/message'  # channelにMessageを送る
C_ACTION_RESULT = 'cmd/ch/action-result'  # cmdの結果を返す
