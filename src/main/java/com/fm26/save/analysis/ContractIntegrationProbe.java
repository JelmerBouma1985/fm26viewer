package com.fm26.save.analysis;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;

public final class ContractIntegrationProbe {

    private ContractIntegrationProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] payload = IsolatedLoanExtractor.loadPayload(Path.of("games/Feyenoord_after.fm"));
        Method resolveContractData = GenericPlayerSubsetExtractor.class.getDeclaredMethod("resolveContractData", byte[].class, int.class);
        resolveContractData.setAccessible(true);

        List<Integer> ids = List.of(
                16023929,
                37060899,
                653054,
                2000040347,
                2000259904,
                2000190514,
                89054469
        );
        for (Integer id : ids) {
            Object contract = resolveContractData.invoke(null, payload, id.intValue());
            Method salaryPerWeek = contract.getClass().getDeclaredMethod("salaryPerWeek");
            Method salaryPerWeekRaw = contract.getClass().getDeclaredMethod("salaryPerWeekRaw");
            Method contractEndDate = contract.getClass().getDeclaredMethod("contractEndDate");
            Method loanExpiryDate = contract.getClass().getDeclaredMethod("loanExpiryDate");
            Method parentContractEndDate = contract.getClass().getDeclaredMethod("parentContractEndDate");
            salaryPerWeek.setAccessible(true);
            salaryPerWeekRaw.setAccessible(true);
            contractEndDate.setAccessible(true);
            loanExpiryDate.setAccessible(true);
            parentContractEndDate.setAccessible(true);
            System.out.println(id
                    + " salary=" + salaryPerWeek.invoke(contract)
                    + " raw=" + salaryPerWeekRaw.invoke(contract)
                    + " contract=" + contractEndDate.invoke(contract)
                    + " loan=" + loanExpiryDate.invoke(contract)
                    + " parent=" + parentContractEndDate.invoke(contract));
        }
    }
}
