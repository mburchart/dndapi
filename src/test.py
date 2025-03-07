from user import User

#user = User(1, "admin", "admin", "admin", "admin", "admin", "123", "123")
#import asyncio

#async def check_permission():
#	perm = await user.has_permission("admin")
#	print(perm)

#asyncio.run(check_permission())
			
print(User.hash_password("pw"))
