namespace Autenticacao_Identity.Models
{
    public class Usuario
    {
        public string Id { get; set; }
        public string Nome { get; set; }
        public string Senha { get; set; }
        public string Role { get; set; }

        public void CleanPassword()
        {
            this.Senha = "";
        }
    }
}