#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
微信 HTTP API 测试脚本

使用方法：
    python test_api.py

需要安装：
    pip install requests
"""

import requests
import json
from typing import Optional


# API 基础地址
BASE_URL = "http://localhost:19088"


def print_response(response: requests.Response, title: str = ""):
    """打印响应结果"""
    print(f"\n{'='*60}")
    if title:
        print(f"【{title}】")
    print(f"状态码: {response.status_code}")
    try:
        data = response.json()
        print(f"响应内容:{data}")
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"响应内容: {response.text}")
    print(f"{'='*60}\n")
    return data


def test_health():
    """测试健康检查和 API 列表"""
    print("测试健康检查...")
    response = requests.get(f"{BASE_URL}/api/health")
    print_response(response, "健康检查")
    return response.json() if response.status_code == 200 else None


def test_check_login():
    """测试检查登录状态"""
    print("测试检查登录状态...")
    response = requests.get(f"{BASE_URL}/api/checkLogin")
    print_response(response, "检查登录状态")
    return response.json() if response.status_code == 200 else None


def test_contacts_self():
    """测试获取自己的信息"""
    print("测试获取自己的信息...")
    response = requests.get(f"{BASE_URL}/api/contacts/self")
    print_response(response, "获取自己的信息")
    return response.json() if response.status_code == 200 else None


def test_contacts_list():
    """测试获取联系人列表"""
    print("测试获取联系人列表...")
    response = requests.get(f"{BASE_URL}/api/contacts")
    print_response(response, "获取联系人列表")
    return response.json() if response.status_code == 200 else None


def test_contact_detail(contact_id: str):
    """测试获取联系人详情"""
    print(f"测试获取联系人详情: {contact_id}")
    response = requests.get(f"{BASE_URL}/api/contact", params={"contactId": contact_id})
    print_response(response, f"获取联系人详情: {contact_id}")
    return response.json() if response.status_code == 200 else None


def test_rooms_list():
    """测试获取群聊列表"""
    print("测试获取群聊列表...")
    response = requests.get(f"{BASE_URL}/api/rooms")
    print_response(response, "获取群聊列表")
    return response.json() if response.status_code == 200 else None


def test_room_detail(room_id: str):
    """测试获取群聊详情"""
    print(f"测试获取群聊详情: {room_id}")
    response = requests.get(f"{BASE_URL}/api/room", params={"roomId": room_id})
    print_response(response, f"获取群聊详情: {room_id}")
    return response.json() if response.status_code == 200 else None


def test_send_text_message(contact_id: str, text: str, at_wxids: Optional[list] = None):
    """测试发送文本消息"""
    print(f"测试发送文本消息到: {contact_id}")
    data = {
        "contactId": contact_id,
        "text": text
    }
    if at_wxids:
        data["atWxids"] = at_wxids
    
    response = requests.post(
        f"{BASE_URL}/api/message/text",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    print_response(response, f"发送文本消息到: {contact_id}")
    return response.json() if response.status_code == 200 else None


def test_send_image_message(contact_id: str, image_path: str):
    """测试发送图片消息"""
    print(f"测试发送图片消息到: {contact_id}")
    data = {
        "contactId": contact_id,
        "path": image_path
    }
    response = requests.post(
        f"{BASE_URL}/api/message/image",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    print_response(response, f"发送图片消息到: {contact_id}")
    return response.json() if response.status_code == 200 else None


def test_send_file_message(contact_id: str, file_path: str):
    """测试发送文件消息"""
    print(f"测试发送文件消息到: {contact_id}")
    data = {
        "contactId": contact_id,
        "path": file_path
    }
    response = requests.post(
        f"{BASE_URL}/api/message/file",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    print_response(response, f"发送文件消息到: {contact_id}")
    return response.json() if response.status_code == 200 else None


def test_send_pat_message(room_id: str, contact_id: str):
    """测试发送拍一拍消息"""
    print(f"测试发送拍一拍消息: {room_id} -> {contact_id}")
    data = {
        "roomId": room_id,
        "contactId": contact_id
    }
    response = requests.post(
        f"{BASE_URL}/api/message/pat",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    print_response(response, f"发送拍一拍消息")
    return response.json() if response.status_code == 200 else None


def test_forward_message(msg_id: int, receiver: str):
    """测试转发消息"""
    print(f"测试转发消息: {msg_id} -> {receiver}")
    data = {
        "msgId": msg_id,
        "receiver": receiver
    }
    response = requests.post(
        f"{BASE_URL}/api/message/forward",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    print_response(response, f"转发消息")
    return response.json() if response.status_code == 200 else None


def test_db_names():
    """测试获取数据库列表"""
    print("测试获取数据库列表...")
    response = requests.get(f"{BASE_URL}/api/db/names")
    print_response(response, "获取数据库列表")
    return response.json() if response.status_code == 200 else None


def test_db_tables(db_name: str):
    """测试获取表列表"""
    print(f"测试获取表列表: {db_name}")
    response = requests.get(f"{BASE_URL}/api/db/tables", params={"dbName": db_name})
    print_response(response, f"获取表列表: {db_name}")
    return response.json() if response.status_code == 200 else None


def test_db_query(db_name: str, sql: str):
    """测试执行 SQL 查询"""
    print(f"测试执行 SQL 查询: {db_name}")
    data = {
        "dbName": db_name,
        "sql": sql
    }
    response = requests.post(
        f"{BASE_URL}/api/db/query",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    print_response(response, f"执行 SQL 查询: {db_name}")
    return response.json() if response.status_code == 200 else None


def main():
    """主函数 - 运行所有测试"""
    print("="*60)
    print("微信 HTTP API 测试脚本")
    print("="*60)
    
    # 检查服务器是否可用
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if response.status_code != 200:
            print(f"❌ 服务器不可用，状态码: {response.status_code}")
            return
    except requests.exceptions.ConnectionError:
        print(f"❌ 无法连接到服务器 {BASE_URL}")
        print("请确保：")
        print("1. 微信已启动并登录")
        print("2. Frida 脚本已加载（运行: npm run start:wx391027）")
        print("3. HTTP 服务器正在运行（端口 19088）")
        return
    except Exception as e:
        print(f"❌ 连接错误: {e}")
        return
    
    print("✅ 服务器连接成功！\n")
    
    # 基础信息测试
    test_health()
    test_check_login()
    
    # 联系人测试
    test_contacts_self()
    contacts_result = test_contacts_list()
    
    # 如果有联系人，测试获取第一个联系人详情
    if contacts_result and contacts_result.get("code") == 1:
        contacts = contacts_result.get("data", [])
        if contacts and len(contacts) > 0:
            first_contact = contacts[0]
            contact_id = first_contact.get("id") or first_contact.get("wxid")
            if contact_id:
                test_contact_detail(contact_id)
                # 测试发送文本消息（取消注释以启用）
                # test_send_text_message(contact_id, "这是一条测试消息")
    
    # 群聊测试
    rooms_result = test_rooms_list()
    
    # 如果有群聊，测试获取第一个群聊详情
    if rooms_result and rooms_result.get("code") == 1:
        rooms = rooms_result.get("data", [])
        if rooms and len(rooms) > 0:
            first_room = rooms[0]
            room_id = first_room.get("id") or first_room.get("wxid")
            if room_id:
                test_room_detail(room_id)
                # 测试发送群聊消息（取消注释以启用）
                # test_send_text_message(room_id, "这是一条群聊测试消息")
    
    # 数据库测试
    db_names_result = test_db_names()
    
    # 如果有数据库，测试获取第一个数据库的表列表
    if db_names_result and db_names_result.get("code") == 1:
        db_names = db_names_result.get("data", [])
        if db_names and len(db_names) > 0:
            first_db = db_names[0]
            test_db_tables(first_db)
            # 测试执行 SQL 查询（取消注释以启用）
            # test_db_query(first_db, "SELECT name FROM sqlite_master WHERE type='table' LIMIT 5")
    
    print("\n" + "="*60)
    print("测试完成！")
    print("="*60)
    print("\n提示：")
    print("- 要测试发送消息功能，请取消脚本中相应行的注释")
    print("- 修改 contact_id、room_id 等参数为实际的值")
    print("- 确保图片/文件路径存在且可访问")


if __name__ == "__main__":
    # 可以在这里自定义测试参数
    # 例如：
    # test_send_text_message("wxid_xxx", "测试消息")
    # test_send_image_message("wxid_xxx", "C:\\path\\to\\image.jpg")
    # test_send_file_message("wxid_xxx", "C:\\path\\to\\file.pdf")
    # test_send_pat_message("xxx@chatroom", "wxid_xxx")
    # test_forward_message(123456, "wxid_xxx")
    # test_db_query("MicroMsg.db", "SELECT * FROM Contact LIMIT 10")
    
    main()
