from requests import Session
import random
session = Session()

# res = session.post('http://studybonus1.pythonanywhere.com/api/register',json = {
#     'username':'testuser',
#     'password':'testuser'
# })
# print(res.json())

res = session.post('http://studybonus1.pythonanywhere.com/api/login',json = {
    'username':'testuser',
    'password':'testuser'
})
print(res.json())

# res_info = session.get('http://studybonus1.pythonanywhere.com/api/account/others_info?id=90')
# print(res_info.json())

# res_get_random_question = session.get('http://studybonus1.pythonanywhere.com/api/study/random_question_from_all')
# print(res_get_random_question.json())

res_get_all_questions = session.get('http://studybonus1.pythonanywhere.com/api/study/get_all_question_by_unit?unit=1')
print(res_get_all_questions.json())

# print(session.cookies.get_dict())

# res_coin = session.get('http://studybonus1.pythonanywhere.com/api/account/coin')
# print(res_coin.json())

# res_upgrade = session.post('http://studybonus1.pythonanywhere.com/api/account/upgrade')
# print(res_upgrade.json())

# res_coin = session.get('http://studybonus1.pythonanywhere.com/api/account/coin')
# print(res_coin.json())

# res_add_coin = session.post('http://studybonus1.pythonanywhere.com/api/study/coin/add')
# print(res_add_coin.json())


# res_delete_account = session.delete('http://studybonus1.pythonanywhere.com/api/account/delete')
# print(res_delete_account.json())