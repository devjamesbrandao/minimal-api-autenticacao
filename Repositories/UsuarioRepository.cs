namespace Autenticacao_Identity.Repositories
{
    public static class UsuarioRepository
    {
        public static Usuario Get(string usuario, string senha)
        {
            var usuarios = new List<Usuario>
            {
                new Usuario { Id = "1", Nome = "Kakashi", Role = "manager", Senha = "123" },
                new Usuario { Id = "2", Nome = "Shikamaru", Role = "employee", Senha = "123" }
            };

            return usuarios.Where(x => x.Nome.ToLower() == usuario.ToLower() && x.Senha == senha).FirstOrDefault();
        }
    }
}