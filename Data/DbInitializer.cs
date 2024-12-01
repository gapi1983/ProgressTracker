using Microsoft.AspNetCore.Identity;

namespace ProgressTracker.Data
{
    public class DbInitializer
    {
        public static async Task SeedRolesAsync(IServiceProvider serviceProvider) 
        {
            // getting role manager service
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

            //defining roles
            string[] roleNames = { "Admin", "Manager","Employee" };

            foreach(var roleName in roleNames)
            {
                var roleExists = await roleManager.RoleExistsAsync(roleName);
                if(!roleExists)
                {
                    //if role does not exists it will create it
                    var roleResult = await roleManager.CreateAsync(new IdentityRole<Guid>(roleName));

                    if (!roleResult.Succeeded)
                    {
                        // Handle errors here
                        throw new Exception("Failed to create role");
                    }
                }
            }
        }
    }
}
